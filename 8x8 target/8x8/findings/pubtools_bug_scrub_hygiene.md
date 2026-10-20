# [Draft] Undocumented local-auth path + stale OAuth redirect on pubtools.private.8x8cloud.net ("Bug Scrub")

STATUS: draft, not yet submitted. Parked while we work the vcc-* slice; come back to
polish before sending.

## Summary
`pubtools.private.8x8cloud.net` (an internal "Bug Scrub" tool run by the GAS Team,
reached via `*.8x8cloud.net`, a bounty-eligible wildcard) is intended to be accessed
only via Google SSO (`/auth/google`), per its own login page. However:
1. A second, fully functional local email/password login path (`GET /local-login`,
   `POST /login`) is live and reachable, even though the link to it has been commented
   out of the main login page's HTML — it was clearly meant to be disabled, not removed.
2. The Google OAuth flow's `redirect_uri` points to `salesforce-case-status.dxi.eu`,
   a domain with no current DNS record (NXDOMAIN) — confirmed via crt.sh to have been
   a real, decommissioned app. The OAuth client config was never updated after that
   app was retired.

Both are configuration/attack-surface hygiene issues rather than a directly
demonstrated exploit — two safe tests against `/local-login` (nonexistent email +
wrong password; malformed email) showed no user-enumeration or error-based
information leak. Rate-limiting on the endpoint is unverified (untested by design —
repeated attempts risk crossing into disallowed automated/brute-force testing).

## Severity (estimate)
**Low.** No demonstrated exploitation path; this is unnecessary exposed attack
surface + a stale/orphaned OAuth config, not a confirmed vuln. Consistent with 8x8's
own Low-tier examples (exposed panels, forgotten endpoints, info disclosure) — matches
prior paid reports like #710368 (exposed .svn) and #907701 (phpinfo exposure) in
class/spirit, though weaker in impact than either.

## Affected asset
`pubtools.private.8x8cloud.net` (wildcard: `*.8x8cloud.net`, bounty-eligible)

## Steps to reproduce
1. `GET https://pubtools.private.8x8cloud.net/login` → note the commented-out
   `<a href="/local-login">Login Locally</a>` in the page source.
2. `GET https://pubtools.private.8x8cloud.net/local-login` → returns `200` with a full
   email+password login form (title: "Login", app self-identifies as "Bug Scrub").
3. `GET https://pubtools.private.8x8cloud.net/auth/google` → `302` to
   `accounts.google.com/o/oauth2/v2/auth?...redirect_uri=https%3A%2F%2Fsalesforce-case-status.dxi.eu%2Fauth%2Fgoogle%2Fcallback...`
4. DNS lookup of `salesforce-case-status.dxi.eu` → NXDOMAIN (SOA only, no A/CNAME).
   crt.sh (`https://crt.sh/?q=%25.dxi.eu`) shows a certificate was issued for this
   exact hostname historically, confirming it was a real, now-decommissioned service.

## Proof of concept
See `../requests/` for saved raw responses (to be added before submission):
- local-login page source
- auth/google redirect Location header
- crt.sh query result showing historical cert for the dead hostname

## Impact
- Expands the attack surface of an internal tool beyond its intended single SSO
  path, with no visible pointer to it (security-by-obscurity that doesn't hold).
- The OAuth misconfiguration is a hygiene finding: since `dxi.eu`'s zone is still
  actively controlled by 8x8/DXI (not a dangling CNAME to a third-party host), an
  outside attacker cannot register that subdomain themselves, which caps the real-world
  exploitability. If 8x8 ever loses control of that specific DNS zone/record, however,
  the misconfigured client would silently start leaking OAuth codes there.

## Suggested fix
- Remove or properly gate `/local-login` and `/signup` if they're not meant to be used
  (they appear to be dead/incomplete — `/signup` itself 404s).
- Update the Google OAuth client's registered redirect URI to the current domain and
  remove the stale `salesforce-case-status.dxi.eu` entry.

## Evidence files
TODO before submission: save raw curl transcripts into `../requests/pubtools_*`.
