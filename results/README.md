# Results data

The three runs behind the numbers in the main README and in `docs/RESULTS.md`.

| Folder | What it is |
|---|---|
| `gemini_20261012T143042Z_991503` | live run, `gemini-3.5-flash-lite`, 27 sessions |
| `gemini_20261012T151134Z_5ae09e` | live run, `gemini-3.1-flash-lite`, 27 sessions |
| `replay_20261012T153231Z_9c1563` | replay run (scripted tool calls, no LLM), 27 sessions |
| `original_harness/` | the exact `lab.py` and `cases.json` that produced the three runs |

The runs were made with Vietnamese prompts and payloads, so the prompts and model answers
in these folders are in Vietnamese.

## Files in a run folder

| File | Content |
|---|---|
| `manifest.json` | model, temperature, seed, case list, SHA-256 of the harness and the cases |
| `results.csv` | one row per session |
| `summary.csv` / `summary.json` | ASR and control counts per configuration |
| `events.jsonl` | every event: context retrieved, tool request (with gate decision), tool result, model response |
| `findings.csv` / `findings.json` | output of the detection rules |
| `quality_review.csv` | empty template for a manual quality review |
| `sessions/<trace_id>/` | `prompt.json`, `context.txt`, `responses.jsonl` (raw API responses, live runs only), `answer.txt`, `before.json`, `after.json`, `result.json` |

## Checking the hashes

Every manifest records `lab_sha256` and `cases_sha256`. All three runs have:

```
lab_sha256   0395887349c266adc706ec15e8fa111710aba605781a7ad21100033bebef4cf1
cases_sha256 4616c9761dc5e37debd07549fac5ec113e5bebc4b643e45865a7736ba2b8d240
```

They match the files in `original_harness/`:

```bash
python -c "import hashlib,pathlib; b=pathlib.Path('results/original_harness'); [print(n, hashlib.sha256((b/n).read_text(encoding='utf-8').encode('utf-8')).hexdigest()) for n in ('lab.py','cases.json')]"
```

`cases/cases.vi.json` in the repository root is the same file as
`original_harness/cases.json`. The `lab.py` in the repository root is the English
translation of the original script with a `--lang` switch; its hash is different, and new
runs will record the new hash.

No API key, request header or personal data is stored in these folders.
