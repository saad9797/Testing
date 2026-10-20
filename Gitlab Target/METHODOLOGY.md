# Bug Hunting Playbook — built from the full 8x8 engagement

Load this at the start of any hunting session (same target or a new one). It's both
a behavioral contract (how to operate) and a case study (exactly what happened on
8x8, step by step, so the pattern is concrete, not abstract).

---

## 1. SESSION BEHAVIOR CONTRACT — read this first, every time

**Default mode is thorough and deep. Do not stop after one or two checks on a
promising host.** The real finding in this engagement came from following a chain
of six discoveries from a single starting page — not from one clever test:

```
CM/login.php (view source)
  -> pulled CM/js/login.js
    -> found gen_check_tenant_admin.php (undocumented pre-auth endpoint)
      -> tested it -> found real SQLi signal -> reported
  -> the SAME login.js also referenced admin_forgot_password.php
    -> pulled that page
      -> pulled its JS (admin_forgot_password.js)
        -> found gen_check_redirection.php (sibling endpoint)
          -> tested it -> inconclusive, logged, moved on
  -> pivoted to AGUI/login.php (a separate app in the same product)
    -> pulled AGUI/js/login.js AND AGUI/js/login_shared.js (both, not just one)
      -> found a hardcoded API key -> assessed against policy, logged, didn't chase
      -> found gen_check_tenant_agent.php -> tested a real hypothesis -> disproven
      -> found isSafeLoginRedirectURL() -> recognized as an already-patched bug -> logged
```

That's the standard: **every page you fetch, pull every `<script src=...>` it
references — not just the first one.** Every AJAX/fetch call in that JS is a
potential undocumented endpoint. Every one of those gets at least the baseline test
in the escalation ladder (Section 4). Every new reference found *inside* one of
those files (another `.php` endpoint, another JS file, a forgot-password link, a
sibling in the same backend directory) goes on the list and gets pulled too.

**Only stop pursuing a specific thread when one of these is true:**
- You've hit the point in the escalation ladder where continuing risks production
  impact (Section 4, step 4) — evidence in hand, time to write it up.
- The next step needs something you don't have (a real account, real customer data,
  credentials) — log it as blocked, don't fake around it.
- You tested a live hypothesis and it failed (Section 5 has the disproven-enumeration
  example) — log the negative result with the actual data, and stop repeating that
  specific test, but keep pulling other threads on the same host/app.
- You've genuinely run out of new references to follow on this host/app (no new JS
  files, no new endpoint mentions, nothing left un-pulled) — only then is a slice
  "done," and that should be stated explicitly, not just quietly dropped.

**Don't ask for permission between every micro-step of exploring one application.**
Fetch the page, fetch the JS, read it, test the baseline, report what you found —
in one continuous pass. **Only check in for an explicit go/no-go at real escalation
points**: before moving from "observe behavior" to "inject a boolean/timing payload,"
before any action that could be state-changing (submitting a real form, triggering
an email), or when you've found something serious enough that continuing could
affect production. Section 4 and Section 6 define exactly where those lines are —
they don't move just because the instruction is "go deep."

---

## 2. TARGET VETTING (do this before touching anything)

1. Pull the program's scope page and its **structured scope CSV**
   (`teams/<handle>/assets/download_csv.csv` on HackerOne). Parse
   `eligible_for_bounty=true` vs `false`. On 8x8: **only 21 of 138 scope entries
   were bounty-eligible** — most of what "looks" in-scope pays nothing. Never assume;
   check the CSV every time.
2. Read the **full policy page** verbatim, save it into `scope.md`. Capture: mandatory
   identification header (8x8 required `X-HackerOne: <username>` on every request),
   testing-conduct bans (no automated/high-volume testing, no credential stuffing, no
   spam), and every scope exclusion (8x8 excluded UUID-based IDORs, missing security
   headers, self-XSS, etc. — check what's excluded before you spend time on it).
3. Pull program health stats directly off the page: total paid, avg bounty per
   severity, reports/90 days, response efficiency. 8x8: $488,735 paid, avg $500,
   ~621 reports/90 days (~7/day — busy, expect duplicates), 100% response efficiency,
   ~1hr first response.
4. Read **every publicly disclosed report** for the program (via a stats aggregator
   page or Hacktivity). This is your real priority list of bug classes — not a
   generic checklist. 8x8's history: information disclosure, XSS, subdomain
   takeover, auth bypass, one SQLi (#922567) — that last one directly justified
   prioritizing the login/auth flow that eventually produced a real finding.
5. Check whether eligible apps offer self-signup test accounts. 8x8's Express
   self-serve trial was discontinued in 2023; eligible apps explicitly state no test
   creds provided. This caps you to pre-auth testing unless you get access another
   way — know this constraint going in, don't discover it mid-engagement.

## 3. WORKSPACE STRUCTURE (repeat this shape per target)

```
<target>/
├── README.md
├── scope.md              — policy, VERBATIM, re-verify every session
├── THREAT_MODEL.md         — crown jewels, invariants, attacker model, priorities
├── recon/                  — scope CSV, subdomain lists, httpx output
├── requests/                 — raw evidence, one saved file per test performed
├── notes/hypotheses.md       — running log of EVERY test, including negatives
└── findings/                 — one file per candidate vuln, one vuln per file
```
Tools: `subfinder`, `httpx`, `ffuf`, `subzy` (`go install .../cmd/<tool>@latest`).
If a full wordlist repo clone is flaky, pull specific files by raw URL instead of
fighting it.

## 4. THE ESCALATION LADDER — how to test any endpoint you find

Applied every time you find a new backend endpoint via JS analysis:

1. **Baseline.** Call it with an obviously synthetic value. Record the exact
   response shape and timing — this is your control for everything after.
2. **Single metacharacter test.** One request with a quote or angle bracket in the
   suspect parameter. Compare to baseline: filtered/encoded, or verbatim passthrough?
   (On `gen_check_tenant_admin.php`, `bar'or'1'='1` came back completely unescaped —
   that one request told us input handling was absent.)
3. **If unfiltered: exactly two more requests, not a payload campaign.**
   - a condition that's universally TRUE regardless of any real data
     (`foo@' OR '1'='1`)
   - a condition that's universally FALSE regardless of any real data
     (`foo@' OR '1'='2`)
   Compare timing and content. A dramatic differential here, on top of step 2's
   unfiltered passthrough, is enough standard evidence to write an honest report.
4. **STOP.** No `SLEEP()` payloads, no UNION extraction, no repeating a request that
   already produced an abnormal hang. On 8x8, the TRUE-condition request alone
   caused a 20+ second hang against what was very likely production — that one data
   point was sufficient and repeating it would only add risk for no new evidence.
5. **If a hypothesis fails, that's a real result — log it, don't force it.** On
   AGUI's `gen_check_tenant_agent.php`, the client JS suggested a `uidsMatch` field
   would reveal whether an account exists (pre-auth enumeration). Six synthetic
   tests showed `uidsmatch=true` for literally any non-empty tenant — it's an
   empty-field check, not an existence check. Correctly killed before writing a
   report on it. **Reading code suggests a hypothesis; only live testing confirms
   or kills it.**

## 5. HARD SAFETY BOUNDARIES — fixed regardless of how deep you go

- Never target real/plausible customer or tenant identifiers — test the *mechanism*
  with synthetic values only. The boolean test above (`'1'='1'` vs `'1'='2'`) was
  built specifically to never depend on any real tenant existing.
- Never complete a state-changing action with synthetic data if it might hit a real
  account (password-reset submission, lockout-notification email triggers). On 8x8,
  `admin_forgot_password.php`'s actual POST and `gen_send_lock_mail.php` were both
  identified via JS but never invoked, specifically because either could plausibly
  email a real person.
- Never repeat a test that already caused an anomalously slow response.
- Treat automated safety-classifier blocks as correct signal, not an obstacle — don't
  reroute the same action through a different tool or phrasing.
- Client-side API keys found in JS are typically explicitly out of scope unless you
  can demonstrate concrete abuse *and* a fix (8x8's own policy says this outright).
  Don't sink effort trying to weaponize a bare RUM/telemetry key you can't complete
  the abuse chain on.

## 6. REPORT FORMAT — exact template, with real worked examples

**One vulnerability per report** (HackerOne platform standard — the only exception
is multiple symptoms of one shared root cause). Two independent issues on the same
host still get two separate reports — we split a combined pubtools draft into two
for exactly this reason.

### Field-by-field structure (used for every report regardless of platform form layout)

```
Title:            <short, technical, names the vulnerable file/endpoint>
Weakness/CWE:     <closest match — don't overthink it if imperfect>
Asset:            <the eligible wildcard/domain from the scope CSV — prefer the
                   parent wildcard over one specific subdomain if the program's
                   policy treats them as one report anyway>
Severity:         <Low/Medium/High/Critical, self-assessed, with a written
                   justification paragraph if the form asks for one>

Description:
  ## Summary:
  [what's broken, how you found it, what the evidence shows, AND a plain statement
   of what you did NOT confirm if evidence is circumstantial]

  ## Steps To Reproduce:
    1. [exact request/action]
    1. [exact request/action]
    1. [exact request/action]
       (numbering all lines "1." is fine — most renderers auto-number)

  ## Supporting Material/References:
    * [attached file] — [what it shows]
    * [attached file] — [what it shows]
    * [link to any related historical report you're citing for severity context]

Impact:           <separate field if the form has one — concrete, conditional
                   language ("if confirmed," "could potentially"), not overclaimed>

Attachments:      <every file referenced above, actually saved to requests/ first>
```

### WORKED EXAMPLE A — High severity (real report, submitted, closed Duplicate)

> **Title:** Pre-authentication Blind SQL Injection in gen_check_tenant_admin.php
> (vcc-* Configuration Manager)
>
> **Weakness:** CWE-89 (SQL Injection)
>
> **Asset:** vcc-na30.8x8.com (policy names this the reference instance for the
> vcc-*.8x8.com wildcard; one report accepted across all vcc-* domains)
>
> **Severity:** High — reason given: *"This is rated High because it is a
> pre-authentication SQL injection — reachable by anyone who loads the
> Configuration Manager login page, with no credentials required — against what is
> very likely the primary tenant/customer database of this product. 8x8 has
> previously paid a High severity bounty for a post-authentication SQL injection in
> this same product (report #922567); this finding requires no authentication at
> all, which is typically assessed as more severe than that precedent. The evidence
> ... is strong and consistent with real SQL injection, though I have not extracted
> actual data to confirm exploitability further — I stopped testing after the
> boolean-timing check because it already caused an unexpected ~20+ second delay
> against what appears to be production infrastructure, and did not want to risk
> additional service impact. I'd ask your team to verify server-side."*
>
> **Description — Summary:** *"The `admin` parameter of the unauthenticated endpoint
> `/GEN/gen_check_tenant_admin.php` (called automatically by the Configuration
> Manager login page before any credentials are submitted) is concatenated into a
> backend query without sanitization or apparent parameterization. Testing showed
> SQL metacharacters (including single quotes) pass through completely unescaped,
> and a boolean-based differential test (an always-true vs. always-false injected
> condition) produced a dramatic timing difference consistent with the payload
> reaching a live SQL WHERE clause — the always-true condition caused the server to
> hang beyond a 20-second timeout, while the always-false condition took ~10.7
> seconds, both far above the sub-1-second baseline for ordinary values. This is
> reachable with no authentication at all. I want to be transparent that this
> report is based on strong circumstantial evidence ..., not confirmed data
> extraction. I stopped testing ... because I did not want to risk further service
> impact by probing more aggressively (e.g. via UNION-based extraction)."*
>
> **Steps To Reproduce:**
> 1. Request `https://vcc-na30.8x8.com/CM/login.php` once to establish a session
>    cookie (required — the endpoint redirects without it).
> 1. Using the same cookie, request
>    `GET /GEN/gen_check_tenant_admin.php?type=cm_login&admin=foo@bar'or'1'='1` —
>    the value reflects verbatim and unescaped in `<tenant>`, no error.
> 1. Using the same cookie, request `admin=foo@' OR '1'='1` (always-true) — did not
>    complete within 20 seconds.
> 1. Using the same cookie, request `admin=foo@' OR '1'='2` (always-false) —
>    completed in ~10.7 seconds.
> 1. Compare all three timings against the near-instant response in step 2.
>
> **Impact:** *"If confirmed, an unauthenticated remote attacker (no login required
> ...) could potentially enumerate or extract tenant/customer records from the
> backend database. Depending on database permissions and whether stacked queries
> are possible (as they were in the related historical finding #922567 on this same
> product), potentially modify or delete data."*
>
> **Outcome:** Closed as Duplicate — "we have already received a prior report of
> this vulnerability." No bounty (first-to-report-only policy), but this confirms
> the bug was real and the methodology sound.

### WORKED EXAMPLE B — Low severity (real report, submitted, pending)

> **Title:** Undocumented local-credential login path exposed on
> pubtools.private.8x8cloud.net ("Bug Scrub")
>
> **Weakness:** CWE-284 (Improper Access Control) — closest fit, not a clean match
>
> **Asset:** `*.8x8cloud.net` (the eligible wildcard)
>
> **Severity:** Low — self-assessed honestly, not inflated. No demonstrated
> exploitation path; this is exposed attack surface, not a confirmed vuln.
>
> **Description — Summary:** *"pubtools.private.8x8cloud.net (an internal 'Bug
> Scrub' tool run by the GAS Team) is intended to be accessed only via Google SSO,
> per its own login page. However, a second, fully functional local email/password
> login path (GET /local-login, POST /login) is live and reachable, even though the
> link to it has been commented out of the main login page's HTML — indicating it
> was meant to be disabled, not left live. This is an attack-surface hygiene issue
> rather than a directly demonstrated exploit. Two safe tests against /local-login
> ... showed no user-enumeration or error-based information leak ... Rate-limiting
> ... is unverified by design, since testing it further would require repeated
> login attempts that risk crossing into disallowed automated testing."*
>
> **Steps To Reproduce:**
> 1. Request `/login`, view source — note the commented-out
>    `<a href="/local-login">Login Locally</a>` link.
> 1. Request `/local-login` directly — returns 200 with a full login form (app
>    self-identifies internally as "Bug Scrub").
> 1. Submit a nonexistent email + wrong password to `POST /login` — generic 302,
>    no differentiation.
> 1. Submit a malformed email — identical behavior.
>
> **Impact:** *"This expands the attack surface of an internal tool beyond its
> intended single SSO path, with no visible link pointing to it from the current
> UI. If the local-auth mechanism has weaker protections than the Google SSO path
> (unverified — rate-limiting could not safely be tested), it could become a
> lower-friction path to account compromise than the intended SSO flow."*
>
> **Honest calibration note (said out loud before submitting, not hidden):** this
> is authentic and accurately reported, but a real possibility exists 8x8 already
> knows about this as an intentional break-glass mechanism, which would make the
> correct outcome "Not Applicable," not just a small payout. Submitted anyway —
> honest low-confidence reports are still worth sending; the value is the
> real triage interaction, not a guaranteed check.

## 7. HANDLING OUTCOMES

- **Duplicate = your methodology was validated**, even with $0 payout — the program
  explicitly confirmed the bug was real. Don't read this as failure.
- **Informative/Not Applicable is a normal, frequent outcome** for hygiene findings
  with no demonstrated impact. Calibrate your own expectations before submitting,
  not after — say out loud whether you think this is likely Informative-but-real or
  possibly-not-a-bug-at-all, and submit anyway if it's honest.
- After an outcome, don't linger re-testing the same endpoint family hoping for a
  different result. Follow 1-2 genuinely new leads on the same app if they exist
  (we went CM -> AGUI, a different app in the same product), but recognize
  diminishing returns once the client-side-discoverable surface is covered.
- Periodically zoom out: is this program's eligible, unauthenticated surface
  actually exhausted relative to effort in? A high reports/day program (8x8: ~7/day)
  hits this faster. That's a legitimate reason to rotate targets, not a failure.

## 8. QUICK-REFERENCE CHECKLIST

- [ ] Scope CSV pulled, eligible vs ineligible separated, self-signup checked
- [ ] Full policy saved verbatim, mandatory headers/rate limits noted
- [ ] Disclosed reports read, THREAT_MODEL.md built with real priorities
- [ ] Passive subdomain enum -> eligible filter -> dev/staging/admin prioritized
- [ ] OSINT sweep: npm, DockerHub, GitHub code search (zero-scope PAT)
- [ ] DNS-only takeover sweep, every candidate manually verified
- [ ] httpx eligible hosts, low rate, header attached, results triaged
- [ ] For each live host: full page source + EVERY referenced JS file, no skipping
- [ ] Every endpoint/reference found in JS gets added to the list and pulled too
- [ ] Escalation ladder per endpoint: baseline -> metachar test -> boolean-diff -> STOP
- [ ] Hypotheses tested live before write-up; disproven ones logged, not forced
- [ ] One bug per report, severity justified against program precedent, evidence
      files saved to requests/ before submitting
- [ ] Duplicate = validation; Informative = normal; keep pulling new threads until
      the surface is genuinely exhausted, then reassess whether to rotate targets
