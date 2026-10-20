# [Draft] Undocumented local-credential login path exposed on pubtools.private.8x8cloud.net ("Bug Scrub")

STATUS: draft, ready for polish/submission. Split out from an earlier combined draft —
HackerOne's platform standard is one vulnerability per report except where multiple
symptoms share one root cause; this and the stale-OAuth-redirect finding are two
independent root causes on the same host, so they're filed separately.

## Summary
`pubtools.private.8x8cloud.net` (an internal "Bug Scrub" tool run by the GAS Team,
reached via `*.8x8cloud.net`, a bounty-eligible wildcard) is intended to be accessed
only via Google SSO (`/auth/google`), per its own login page's instructions. However,
a second, fully functional local email/password login path (`GET /local-login`,
`POST /login`) is live and reachable, even though the link to it has been commented
out of the main login page's HTML — indicating it was meant to be disabled, not left
live.

This is a configuration/attack-surface hygiene issue rather than a directly
demonstrated exploit. Two safe tests against `/local-login` (nonexistent email +
wrong password; malformed email) showed no user-enumeration or error-based
information leak. Rate-limiting on the endpoint is unverified by design — repeated
attempts would risk crossing into disallowed automated/brute-force testing.

## Severity (estimate)
**Low.** No demonstrated exploitation path; this is unnecessary exposed attack
surface, not a confirmed vuln. Consistent with 8x8's own Low-tier examples (exposed
panels, forgotten endpoints) — similar in class/spirit to prior paid reports like
#710368 (exposed .svn) and #907701 (phpinfo exposure), though weaker in impact than
either since no data or error information was shown to leak.

## Affected asset
`pubtools.private.8x8cloud.net` (wildcard: `*.8x8cloud.net`, bounty-eligible)

## Steps to reproduce
1. `GET https://pubtools.private.8x8cloud.net/login` → note the commented-out
   `<a href="/local-login">Login Locally</a>` in the page source.
2. `GET https://pubtools.private.8x8cloud.net/local-login` → returns `200` with a full
   email+password login form (title: "Login", app self-identifies internally as
   "Bug Scrub").
3. (Optional, already performed) `POST /login` with a nonexistent email + wrong
   password → `302` to `/login`, generic behavior, no visible error differentiation
   between a malformed and a well-formed-but-nonexistent email.

## Proof of concept
See `../requests/`:
- `pubtools_01_login_page.html` + headers — the main login page, showing the
  commented-out `<a href="/local-login">Login Locally</a>` link
- `pubtools_02_local_login_page.html` + headers — the live `/local-login` form
- `pubtools_03_testA_body.txt` + headers — nonexistent email + wrong password test
- `pubtools_04_testB_body.txt` + headers — malformed email test

## Impact
Expands the attack surface of an internal tool beyond its intended single SSO path,
with no visible link pointing to it from the current UI (the only reference is a
commented-out HTML anchor) — security-by-obscurity that doesn't actually hold, since
the route is still reachable by anyone who requests it directly. If the local-auth
mechanism has weaker protections than the Google SSO path (unverified — rate-limiting
could not safely be tested), it could become a lower-friction path to account
compromise than the intended SSO flow.

## Suggested fix
Remove `/local-login` (and the related dead `/signup` route, which itself 404s)
entirely if local auth is not meant to be supported, rather than leaving the backend
route live after removing only the UI link to it.

## Evidence files
All saved in `../requests/`: `pubtools_01_login_page.html`, `pubtools_01_login_headers.txt`,
`pubtools_02_local_login_page.html`, `pubtools_02_local_login_headers.txt`,
`pubtools_03_testA_body.txt`, `pubtools_03_testA_headers.txt`,
`pubtools_04_testB_body.txt`, `pubtools_04_testB_headers.txt`.
