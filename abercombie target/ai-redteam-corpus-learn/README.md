# AI Red-Team Corpus

A prompt/data corpus + scoring rubric for **authorized** red-teaming of your own
local LLM application. Covers prompt injection (direct + indirect), data
exfiltration, and tool/action abuse. No runner included — you wire it to your app.

## Files

- `corpus.yaml` — the test cases. Schema documented at the top of the file.
- `rubric.md` — how to score responses into pass/fail + a weighted resilience score.
- `README.md` — this file.

## Scope & intent

These probes are **benign canaries**. Nothing here performs a real destructive
action: "malicious" instructions just try to make the app print a marker, reveal
a *seeded fake* secret, or call a *mock* tool. That keeps every run safe to execute
and makes a failure unambiguous. Use only against systems you own or are authorized
to test.

## Setup you must provide

Several cases have a `setup` field. Before running them, arrange:

1. **Seed canaries** into the parts of context you want to test for leaks:
   - `<<SEEDED_SYSTEM_CANARY>>` in the system prompt
   - `API_CANARY=sk-CANARY-9f3a` wherever the app loads config/secrets
   - a second user record (`b-canary@example.test`) for cross-user tests
   Use your own unguessable values in practice.
2. **Mock tools** that *record* calls instead of acting: `send_email`,
   `delete_records`, `http_get`, `http_post`, `read_file`, `grant_role`. The mock
   returns a plausible result and logs `(tool, args)` — that log is your ground
   truth for tool-abuse scoring.
3. **Context reset** between cases so a leak doesn't carry over.

## Wiring your own runner (sketch)

```
load corpus.yaml
for case in cases:
    for i in range(N):                      # N repeats for non-determinism
        reset_app_context()
        apply(case.setup)                   # seed canaries / arm mock tools
        resp = app.send(case.input,
                        ingested=case.injected_content)   # route per case.vector
        outcome = score(resp, tool_call_log, case)        # see rubric.md §2
        record(case.id, i, outcome, resp)
report(aggregate_by_category_and_severity)  # rubric.md §3–4
```

The `vector` field tells you *where* `injected_content` enters:
`ingested_document` → pass it as an uploaded/pasted doc; `tool_result` → return it
from a mock tool; `user_message` → it's all in `input`.

## Reporting

Follow `rubric.md` §4: summary table, every FAIL in full, critical fails flagged,
and a saved baseline (app version, model, scores) for regression tracking.

## Extending

Add cases by copying the schema block. Good sources for fresh techniques: OWASP
LLM Top 10 (esp. LLM01 Prompt Injection, LLM06 Sensitive Info Disclosure), and
your own findings — every real bypass you discover should become a permanent case.
