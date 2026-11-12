"""Print one lab session from start to end: prompt, context, tool calls, model answer.

Read-only. It does not call the API and does not touch lab.py or the run folder.

    python view_session.py --run results/gemini_20261012T151134Z_5ae09e
    python view_session.py A1 D0 --run results/gemini_20261012T151134Z_5ae09e
    python view_session.py A1 D0 --run results/gemini_20261012T151134Z_5ae09e --raw
    python view_session.py A1 D0            # newest folder in runs/
"""
import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LINE = "=" * 78
THIN = "-" * 78


def newest_run(runs):
    folders = [p for p in runs.iterdir() if p.is_dir() and (p / "results.csv").is_file()] \
        if runs.is_dir() else []
    if not folders:
        sys.exit(f"No run found in {runs}. Pass one with --run, e.g. a folder in results/.")
    return max(folders, key=lambda p: p.name)


def rows_of(path):
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def short(value, limit=900):
    text = value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=False, indent=2)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more characters]"


def block(title):
    print(f"\n{LINE}\n{title}\n{LINE}")


def show_prompt(folder):
    data = json.loads((folder / "prompt.json").read_text(encoding="utf-8"))
    block("[1] SYSTEM INSTRUCTION sent to the model")
    print(data["system"])
    block("[2] USER MESSAGE: analyst task + retrieved data (the payload is in here)")
    print(data["user"])


def show_tools():
    block("[3] TOOL DECLARATIONS given to the model")
    import lab  # noqa: PLC0415 - imported here so the list is the real one
    for d in lab.function_declarations():
        args = ", ".join(d["parameters"]["required"])
        flag = "  [WRITE]" if d["name"] in lab.WRITES else ""
        print(f"  {d['name']}({args}){flag}\n      {d['description']}")


def show_events(folder, run):
    block("[4] WHAT HAPPENED, step by step (from events.jsonl)")
    trace = folder.name
    events = []
    with (run / "events.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            event = json.loads(line)
            if event.get("trace_id") == trace:
                events.append(event)

    for e in events:
        kind = e["event_type"]

        if kind == "context_retrieved":
            print(f"\n[application] pre-reads the document: {e.get('source_id')}")
            print(f"              sha256 = {e.get('source_sha256', '')[:16]}...")
            print(THIN)
            print(short(e.get("prompt_raw", "")))
            print(THIN)

        elif kind == "model_response":
            print(f"\n>>> MODEL, turn {e.get('turn')} "
                  f"(finishReason={e.get('finish_reason')}, "
                  f"modelVersion={e.get('model_version')})")
            text = (e.get("text") or "").strip()
            print(short(text, 2000) if text else "(no text, function calls only)")
            for call in e.get("proposed_calls") or []:
                print(f"    functionCall -> {call.get('name')} "
                      f"{json.dumps(call.get('args', {}), ensure_ascii=False)}")

        elif kind == "tool_request":
            mark = "ALLOW" if e.get("authz_decision") == "allow" else "DENY "
            print(f"\n[gate]    {mark} {e.get('tool_name')} "
                  f"{json.dumps(e.get('arguments', {}), ensure_ascii=False)}")
            print(f"          task_scope={e.get('task_scope')}  "
                  f"reason={e.get('policy_reason')}  "
                  f"request_id={e.get('request_id', '')[:8]}")

        elif kind == "tool_result":
            print(f"[backend] {e.get('tool_name')} -> {e.get('tool_outcome')}")
            if e.get("result") is not None:
                print(f"          {short(e['result'], 700)}")

        elif kind == "model_output":
            block("[5] FINAL ANSWER returned to the analyst")
            print(e.get("text") or "(empty)")
            print(f"\n(canary in the final answer: {e.get('output_canary')})")


def show_state(folder):
    block("[6] SYNTHETIC DATA before and after the session")
    for name in ("before.json", "after.json"):
        data = json.loads((folder / name).read_text(encoding="utf-8"))
        alert = data.get("alert", {})
        print(f"  {name:12} status={alert.get('status'):8} "
              f"reason={alert.get('reason', '-')!r:20} "
              f"outbox={len(data.get('outbox', []))}")


def show_findings(run, trace):
    block("[7] FINDINGS raised by the detection rules for this session")
    hits = [r for r in rows_of(run / "findings.csv") if r["trace_id"] == trace]
    if not hits:
        print("  (none)")
    for r in hits:
        print(f"  {r['severity']:7} {r['code']:32} request_id={r['request_id'][:8] or '-'}")


def show_result(row):
    block("[8] ROW in results.csv")
    for k in ("config", "case_id", "kind", "task_scope", "status", "model_write_attempt",
              "model_attack_success", "application_attack_success", "alert_status",
              "outbox_count", "output_canary", "api_calls", "retry_count", "error",
              "model_version", "evidence_kind"):
        print(f"  {k:28} {row.get(k, '')}")


def show_raw(folder):
    raw = folder / "responses.jsonl"
    if not raw.is_file():
        return
    block("[9] RAW API RESPONSES (responses.jsonl)")
    with raw.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            print(f"\n--- API call {i} ---")
            print(short(json.loads(line), 3000))


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Print one lab session.")
    ap.add_argument("case", nargs="?", help="case ID, e.g. A1")
    ap.add_argument("config", nargs="?", help="D0, D1 or D2")
    ap.add_argument("--run", type=Path, default=None, help="run folder (default: newest in runs/)")
    ap.add_argument("--raw", action="store_true", help="also print the raw API JSON")
    args = ap.parse_args()

    run = args.run if args.run else newest_run(ROOT / "runs")
    run = run if run.is_absolute() else (Path.cwd() / run)
    rows = rows_of(run / "results.csv")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))

    print(f"RUN        {run.name}")
    print(f"provider   {manifest['provider']}   model={manifest.get('model_requested') or '-'}"
          f"   temperature={manifest['temperature']}")
    print(f"simulation_only={manifest['simulation_only']}   "
          f"lab_sha256={manifest['lab_sha256'][:16]}...")

    if not (args.case and args.config):
        print(f"\n{len(rows)} sessions in this run. "
              f"Pick one: python view_session.py <case> <config> --run <folder>\n")
        print(f"  {'config':7} {'case':5} {'kind':7} {'alert':7} "
              f"{'model_write':12} {'app_success':12} canary")
        for r in sorted(rows, key=lambda r: (r["config"], r["case_id"])):
            print(f"  {r['config']:7} {r['case_id']:5} {r['kind']:7} "
                  f"{r['alert_status']:7} {r['model_write_attempt']:12} "
                  f"{r['application_attack_success']:12} {r['output_canary']}")
        return

    case, config = args.case.upper(), args.config.upper()
    match = [r for r in rows if r["case_id"] == case and r["config"] == config]
    if not match:
        sys.exit(f"No session {config}/{case} in {run.name}")
    row = match[0]
    folder = run / "sessions" / row["trace_id"]

    print(f"\nSESSION    {config} / {case}  ({row['kind']}, task_scope={row['task_scope']})")
    print(f"trace_id   {row['trace_id']}")

    show_prompt(folder)
    show_tools()
    show_events(folder, run)
    show_state(folder)
    show_findings(run, row["trace_id"])
    show_result(row)
    if args.raw:
        show_raw(folder)


if __name__ == "__main__":
    main()
