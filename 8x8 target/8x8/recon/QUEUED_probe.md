# QUEUED — first live probe of eligible hosts (BLOCKED on H1 username)

This is the first step that actually sends requests to 8x8 infrastructure.
It CANNOT run until we insert your HackerOne username, because 8x8 policy
requires `X-HackerOne: <username>` on every request. It is also rate-limited
to stay within "no automated/high-volume testing."

Replace `H1USER` with your HackerOne username, then run from `8x8/recon/`:

```powershell
$env:Path = "$env:USERPROFILE\go\bin;$env:Path"
$ua = "Mozilla/5.0 (compatible; research; X-HackerOne:H1USER)"
httpx -l priority_hosts.txt `
  -H "X-HackerOne: H1USER" `
  -H "User-Agent: $ua" `
  -rate-limit 5 -threads 5 -timeout 10 `
  -status-code -title -tech-detect -web-server -content-length -location `
  -o httpx_priority.txt -json -jo httpx_priority.json
```

Notes:
- `-rate-limit 5` = max 5 req/s; `-threads 5` = low concurrency. Keep it gentle.
- Start with `priority_hosts.txt` (93 hosts), NOT the full 496 — smaller, faster,
  and it's the high-value subset. Expand to `eligible_hosts.txt` only if needed.
- After this, review httpx_priority.txt for: 200 on admin/dashboard/console pages,
  Grafana/Argo/GitLab/Kibana titles, k8s, directory listings, or unexpected 200s
  on -dev/-staging/-internal hosts. Those become findings/ candidates.

## Then: subdomain takeover check (also needs care/header)
```powershell
subzy run --targets eligible_hosts.txt --hide_fails --output subzy_results.json
```
subzy fingerprints dangling CNAMEs. Review any "VULNERABLE" hits manually before
reporting — confirm the CNAME really points to a claimable third-party service.

## What NOT to do without more thought
- No ffuf content-discovery / brute-forcing yet — that's "high-volume" and needs
  coordination with the program first.
- Do not log into / actively exploit anything found. Capture evidence (screenshot,
  response) and write it up; the user sends the report.
