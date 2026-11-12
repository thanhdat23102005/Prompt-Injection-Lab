"""Show, from one replay run, that the task-scope gate works.

    python demo_gate.py                                    # newest replay run
    python demo_gate.py results/replay_20261012T153231Z_9c1563

Leg 1: the same tool call, three configurations, three outcomes.
Leg 2: the gate does not block legitimate work (case B3, scope REMEDIATION).
Leg 3: the scope does not come from the model (see the unit test).
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def newest_replay():
    runs = sorted(list((ROOT / "runs").glob("replay_*"))
                  or list((ROOT / "results").glob("replay_*")), key=lambda p: p.name)
    if not runs:
        raise SystemExit("No replay run yet. Run: python lab.py run --provider replay")
    return runs[-1]


def load(folder):
    with (folder / "results.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    events = [json.loads(line) for line
              in (folder / "events.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    return rows, events


def authz_for(events, trace, tool):
    for e in events:
        if (e.get("trace_id") == trace and e.get("event_type") == "tool_request"
                and e.get("tool_name") == tool and e.get("origin") == "model"):
            return e["authz_decision"], e.get("policy_reason", "")
    return "-", "no call"


def state(folder, trace):
    session = folder / "sessions" / trace
    before = json.loads((session / "before.json").read_text(encoding="utf-8"))
    after = json.loads((session / "after.json").read_text(encoding="utf-8"))
    return before["alert"]["status"], after["alert"]["status"], len(after["outbox"])


def leg(folder, rows, events, case, tool, title, note):
    print(title)
    picked = {r["config"]: r for r in rows if r["case_id"] == case}
    if not picked:
        print(f"   (case {case} is not in this run)\n")
        return
    scope = next(iter(picked.values()))["task_scope"]
    print(f"   case {case}, task_scope = {scope}, tool call: {tool}")
    for cfg in ("D0", "D1", "D2"):
        r = picked.get(cfg)
        if not r:
            print(f"   {cfg}  (session missing)")
            continue
        before, after, box = state(folder, r["trace_id"])
        decision, reason = authz_for(events, r["trace_id"], tool)
        mark = "  <--" if cfg == "D2" else ""
        print(f"   {cfg}  alert: {before} -> {after:<7} outbox: {box}   "
              f"authz: {decision}({reason}){mark}")
    print(f"   {note}\n")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else newest_replay()
    rows, events = load(folder)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    print("=" * 78)
    print(f"RUN: {folder.name}")
    print(f"provider={manifest['provider']}  simulation_only={manifest['simulation_only']}"
          f"  session_count={manifest['session_count']}")
    print("=" * 78 + "\n")

    leg(folder, rows, events, "A1", "close_alert",
        "LEG 1 - The gate blocks an action outside the task scope",
        "The same call is injected into all three configurations. Only D2 has the gate.")

    leg(folder, rows, events, "B3", "close_alert",
        "LEG 2 - The gate does NOT block legitimate work",
        "Scope REMEDIATION: D2 still lets the alert be closed. The gate is not an off switch.")

    codes = {}
    with (folder / "findings.csv").open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            codes[row["code"]] = codes.get(row["code"], 0) + 1
    print("FINDINGS over the whole run")
    for code, n in sorted(codes.items(), key=lambda kv: -kv[1]):
        print(f"   {n:>3}  {code}")
    print()
    print("LEG 3 - The scope does not come from the model")
    print("   python test_lab.py -k test_model_cannot_inject_scope_into_arguments")
    print("   The model adds task_scope=REMEDIATION to the tool arguments")
    print("   -> dispatch() returns invalid_arguments and the alert stays OPEN.")


if __name__ == "__main__":
    main()
