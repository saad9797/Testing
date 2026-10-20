# 8x8 — HackerOne Bug Bounty Workspace

Program: https://hackerone.com/8x8-bounty

## Layout
- `scope.md` — program rules, pasted verbatim. **Read/update this before every session.**
- `recon/` — subdomains, live hosts, tech stack notes (`targets.md` has a seeded list to verify)
- `requests/` — saved HTTP requests/responses (Burp exports, curl transcripts)
- `notes/hypotheses.md` — running log of what you've tried and why
- `findings/` — one file per candidate bug, from `findings/TEMPLATE.md`

## Before you touch the live target
1. Fill in `scope.md` with the real, current policy (copy-paste, don't paraphrase).
2. Create only test accounts you own. Never touch another user's data or an employee account.
3. No automated scanning beyond what the policy explicitly allows — check rate limits.

## Workflow with Claude Code
Feed it real artifacts, not vague asks:
- "Here's my httpx output in recon/ — what looks worth digging into?"
- "Here's a saved request/response in requests/ — does this response leak anything?"
- "Compare these two requests/responses — same endpoint, two different account IDs."
- "Help me turn notes/hypotheses.md entry #3 into a findings/ writeup."

Claude Code reasons well over concrete output (scan results, HTTP traffic, JS bundles).
It can't usefully "go hack the site" for you — every request against the live target is
yours to send and yours to be responsible for.