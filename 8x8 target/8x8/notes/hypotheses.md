# Running Hypothesis Log

Log every idea you test here — including ones that fail. This is what turns into your
report later, and it's what stops you from re-testing the same thing twice.

Format per entry:

```
## [date] <short hypothesis title>
Target: <host/endpoint>
Idea: <why you think this might be broken>
Test: <what you actually did — request sent, tool used>
Result: <what happened>
Verdict: <dead end / needs more testing / looks like a real bug -> move to findings/>
```

---

## Seed hypotheses (from recon, not yet tested)

- Acquisition-derived domains (fuze.me, callroute.com/io) may have weaker auth/session
  handling than the core 8x8.com app if they haven't been fully migrated onto 8x8's SSO.
- Staging/QA subdomains (dashboard.qa.ai.8x8.com, work-staging.8x8.com) may have verbose
  errors, exposed debug info, or weaker auth than production.
- user-profile.8x8.com / user-profile-staging.8x8.com are good IDOR candidates (name
  implies per-user data by ID).
- 8x8.my.site.com is a Salesforce Community/Experience Cloud site — check for the classic
  Salesforce misconfig (public API access, guest user object permissions).
- admin.8x8.com / admin-resolve.8x8.com — check for auth on discovery, default creds,
  and whether they're reachable without a VPN.

---

## [2026-09-15] Session log — Slice A (OSINT) + Slice B (passive enum)

### Slice A — leaked secrets (executed, safe: no 8x8 infra touched)
- Enumerated 8x8 public npm footprint via registry API. Official org has essentially
  one public pkg: `@8x8/pui-partner-comm`. Downloaded + grepped v0.15.0 tarball.
  RESULT: **clean** — no secrets; only references developer.8x8.com / www.8x8.com.
  Verdict: dead end for this package. Partner-built pkgs (saasquatch, cognidesk,
  pipedream, negreanucalin8x8) NOT yet inspected — TODO.
- GitHub/Postman/DockerHub/APK dorking NOT yet run — needs user's authenticated
  GitHub session. Playbook: findings/slice_A_osint_playbook.md.

### Slice B — passive subdomain enum (executed, safe: subfinder is passive)
- subfinder on 8x8.com/wavecell.com/8x8cloud.net/p8t.us/packet8.net → 4,723 subs
  (raw in recon/subs_raw.txt). packet8.net = reverse-DNS noise, filtered out.
- 496 meaningful hosts on ELIGIBLE wildcards → recon/eligible_hosts.txt
- 93 high-interest (tooling/dev/staging/internal keywords) → recon/priority_hosts.txt

### Seed hypotheses from enum (UNTESTED — probing blocked on H1 username)
- `argo-ui.cloud-mgmt.8x8cloud.net` — Argo CD UI often exposed w/o auth or with
  default/anon access → could leak k8s app config/secrets. HIGH if open.
- `grafana.8x8cloud.net` — Grafana; check default creds admin/admin, anon org access,
  and CVE-2021-43798 path traversal if version is old.
- `gitlab.chalet.8x8.com` — GitLab; check open registration, public internal projects.
- `k8s.8x8cloud.net` / `kubernetes.api.global.chalet.8x8.com` — exposed k8s API/
  dashboard (cf. paid report #1418101).
- `8x8-recordings-{dev,staging,prod}.aws.infra8.8x8cloud.net` — call recordings store;
  check for unauth listing/access.
- `asantos-okta-aws` / `asantos-s3-host-test.cloud-mgmt.8x8cloud.net` — personal-named
  forgotten test infra; prime for takeover/exposure.
- `internal.global.chalet.8x8.com` — named "internal" but publicly resolvable.
- `global-test{,2,3}.chalet.8x8.com`, `idm/ipam/hostauth.staging.sjc01...` — staging.

### [2026-09-15] httpx probe of priority_hosts.txt (93) — username saad101, rate 5/s
Only 3 of 93 internet-reachable (rest = internal-only DNS on *.8x8cloud.net):
- gate-bell-...analytics-staging.oci.infra8.8x8cloud.net [401] Java — auth-protected, skip
- gateway-bell-...analytics-staging... [401] — auth-protected, skip
- wavefront-prometheus-ec2-dev.platformdevops.8x8cloud.net [200] Caddy — INVESTIGATED

**wavefront-prometheus-ec2-dev — VERDICT: dead end (negative result).**
Test: GET / , /graph, /-/healthy, /api/v1/status/{buildinfo,config}, /api/v1/targets,
/metrics, and a bogus path — ALL return 200 with Content-Length 0,
Content-Type application/stream+json, Server: Caddy. Bogus path also 200/0 =>
Caddy catch-all responding empty regardless of path. NOT an exposed Prometheus UI;
no config/targets/metrics leaked. Likely a Wavefront metrics ingest endpoint that
only accepts authed POST. Not worth pursuing for first bounty.

### [2026-09-15] Broad httpx over 496 eligible → ~114 live (recon/httpx_eligible_all.txt)
Triage:
- ~90 hosts = `vcc-*.8x8.com` "Welcome to Configuration Manager" login (nginx/CF).
  ONE app per policy (single report across all vcc-*). Hardened, needs creds. Park.
- api.wavecell.com, fax.wavecell.com [200, 48B] = just "Documentation: developer.8x8.com"
  with full CSP/XFO/HSTS/nosniff header set. Hardened API gateways. DEAD END.
- GitHub Pages on eligible *.8x8cloud.net: cloud8.devrel, socmate-docs,
  wiki.platformdevops → 302 to github.com/pages/auth = private pages that EXIST
  => NOT takeoverable (existing claim). Access is authed. Note only.
- S3/CloudFront 403s: avatars-cdn/files-cdn/voice-sdk/vcc-assets/client-beta =
  403 AccessDenied = bucket exists/locked => not "NoSuchBucket" takeover. Park.
- pubtools.private.8x8cloud.net [302 -> /login] nginx/1.18.0 Ubuntu + Amazon ALB —
  publicly-exposed internal tool w/ login. Pre-auth surface worth a look later.
- analytics-ca/au/eu.8x8.com [401] Java — auth-protected. analytics-activity-prod [530].
- vcc-collaborate-us2.8x8.com [302 -> /login] — separate app from Config Manager.

- subzy REJECTED: no custom-header flag => can't send X-HackerOne => non-compliant.
  Doing takeover detection via DNS-only CNAME sweep instead (task bqggw28e3),
  then manual curl+header verification of any candidate.

### [2026-09-15] Subdomain takeover slice — CLOSED, no vulns (all verified)
DNS CNAME sweep of 496 eligible → 47 CNAMEs (recon/cnames.txt). Candidates:
- HubSpot: 8x8.wavecell.com, webmail.wavecell.com -> *.sites.hubspot.net.
  VERIFIED NOT VULN: both return x-hs-portal-id 587546 + 8x8's custom-branded 404
  => domain IS connected to 8x8's HubSpot portal. (Takeover needs "not connected"/no portal.)
- AWS Amplify: docs.chalet.8x8.com -> main.d3tpcnwkr2ffqi.amplifyapp.com.
  VERIFIED NOT VULN: target returns CloudFront "403 Request blocked" (distribution
  EXISTS). Takeover would be 404/NoSuchDistribution. (CNAME is malformed w/ https://
  prefix — cosmetic DNS misconfig, not exploitable.)
- Canny (feedback.wavecell), Statuspage (status.wavecell), Stripe (bounce), SendGrid
  (mailing), Gmail (imap/smtp) = all claimed/email infra, not web takeover.
=> No takeover. Slice closed.

## AUDIT STATUS (2026-09-15) — honest assessment
Worked so far: passive enum (4723 subs), httpx probe of 496 eligible hosts (~114 live),
Slice A npm footprint, subdomain takeover. ALL easy eligible leads dead-ended:
wavecell APIs hardened, wavefront catch-all, GitHub Pages claimed, S3 locked, no takeover.

Key constraint discovered: eligible apps (work/sso/user-profile/admin/pay/vcc-*) give
NO test creds; self-signup products (connect.8x8.com, jaas.8x8.vc) are INELIGIBLE.
=> Realistic first-bounty paths remaining:
  1. Slice A GitHub dorking for leaked secrets (needs user's GitHub login) — best odds,
     eligible "IP on Public Domains" asset (29 resolved). USER-DRIVEN.
  2. Pre-auth bugs on eligible login pages (work.8x8.com, sso.8x8.com, vcc-* CM,
     user-profile) — hard, most-tested surface.
  3. Get a legit 8x8 trial/customer account -> authenticated testing (IDOR on
     non-UUID ids, logic) on eligible apps. Higher effort, higher reward.
NEXT: pivot to Slice A (user runs GitHub dorks) unless user wants pre-auth login probing.

### [2026-09-15] Slice A — authenticated GitHub code search — CLOSED, no leaks
Ran 8 dorks via GitHub code-search API (read-only fine-grained PAT). All hits = noise:
- Recon/scope aggregators (projectdiscovery, arkadiyt, chaos-list, h1domains, trickest…)
- 8x8's OWN intentional public docs (8x8Cloud/public-developer-docs)
- Third-party SDKs/integrations (DataFire, Pipedream, wavecell wrappers)
- trufflehog's built-in 8x8 detector code (eightxeight.go)
Checked the one real thread — third-party WavecellProvider.php (adamsafril19): keys
loaded from $config, NOT hardcoded. Clean.
=> No 8x8 secret in public code. Slice A closed (public-code portion).

### OVERALL VERDICT (2026-09-15)
All unauthenticated / no-cred eligible surface worked and clean:
Slice A (leaked secrets), Slice B (exposed infra/hosts), subdomain takeover — 0 findings.
This is expected for a mature program (1,295 resolved) with no test creds. Fastest
remaining paths require MORE than passive recon: (1) legit 8x8 account -> authed
IDOR/logic testing on eligible apps; (2) deeper iterative GitHub dorking; (3) reconsider
target selection for a beginner wanting a FAST first bounty.
Token: user must remove PAT from README.md and revoke it (sweep done, found nothing).
[DONE 2026-09-16: PAT stripped from README.md by assistant; user to revoke on GitHub.]

### [2026-09-16] Authenticated track — access reality + pre-auth OAuth probe
- 8x8 Express (self-serve free-trial plan) DISCONTINUED for new customers Mar 2023.
  Current 8x8 Work trials are sales-gated. No instant self-serve eligible account.
- work.8x8.com auth = Spring Security OAuth2 -> sso.8x8.com/v2/oauth/authorize
  (client_id=vos-work, redirect_uri=work.8x8.com/login/oauth2/code/vos-work).
- Pre-auth redirect_uri validation test (5 payloads: external, suffix, userinfo,
  subdomain): ALL returned identical 302 -> /v2/login. => authorize defers to login
  BEFORE validating redirect_uri; real validation is post-login at code issuance.
  CONCLUSION: OAuth redirect_uri/ATO class NOT testable without an account. Not a
  bug by itself. (Header-attributed, ~10 low-volume requests total.)
=> HARD BLOCKER confirmed: no eligible authenticated testing is possible without
   first obtaining a legit 8x8 account. Next action is USER's: (a) 8x8 Work trial via
   sales, or (b) request test access from the program on HackerOne (draft in
   notes/test_access_request.md).

### [2026-09-24] Pre-auth audit continuation (items 1-6) — results
**Item 2 fingerprints (live, header'd):**
- pubtools.private.8x8cloud.net/login [200] = custom "Support Gateway" AngularJS app
  (data-ng-csp, Bootstrap, FontAwesome 5.2.0), nginx/1.18.0. Leaks internal host in JS:
  WEBROOT="http://tools.private.8x8cloud.net". Minor info-disclosure. AngularJS(EOL)=
  possible CSTI but needs reflected sink. STOPPED for go/no-go before deeper testing.
- vcc-* Config Manager = legacy CONTACTUAL platform (favicon /OEM/contactual/...,
  "index.html Version 1.2 Date 06/20/06"). index redirects to CM/login.php. /CM/login.php
  & /AGUI/login.php = 200, /QM/ = 404. Old PHP (2006-era) contact-center code, historically
  bug-rich (past SQLi #922567). Authenticated/active testing = STOPPED for go/no-go.
**Item 5 (actuator/CVE mapping):** work.8x8.com /actuator* all 302 (behind auth) = NOT
  exposed. Jitsi CVEs (44080/44081/39205) target *.jitsi.net/8x8.vc = INELIGIBLE assets =>
  not worth pursuing for bounty regardless of version. voapi.8x8.com (Java/Spring) is
  ineligible.
**Item 3 (JS/source maps):** sso.8x8.com/v2/login bundles -> .map all 404 (no source maps).
  user-profile/apps roots serve no bundles pre-auth (gate to login). Negative.
**Item 1 (npm/docker):**
- npm: confirmed only ONE @8x8 package (@8x8/pui-partner-comm, already clean).
- DockerHub 8x8cloud/* org = 9 real images (ecr-credentials, knox[Vault], kafka/logstash/
  elasticsearch/kibana-in-a-box, centos-vault, fetching/expirycerts-webui). Inspected
  configs (env + build history) of ecr-credentials, knox, fetching-expirycerts,
  expirycerts-webui: NO baked secrets (GPG_KEY = standard Python base-image key; only a
  maintainer email lance.johnson@8x8.com in a label). Deeper layer-FS grep would need
  docker/large pulls — lower priority. wavecellsg/* = alpine base images, low interest.
- More GitHub dorks (Priority 2/3) NOT re-run — earlier authed sweep was clean; PAT to be
  revoked by user. Re-run in-browser if desired.
**Item 4 (takeover):** already completed across full 496-host set earlier — 3 candidates
  (all 8x8.github.io), all claimed. No takeover. CONFIRMED complete.
**Item 6 (API docs):** developer.8x8.com is NOT an eligible asset; only matters if docs
  leak secrets usable vs eligible assets. Not yet reviewed — low priority, pending.

NET: no new confirmed findings. Two items need a USER go/no-go for deeper (active) testing:
(A) pubtools Support Gateway (AngularJS CSTI / app endpoints), (B) vcc legacy Contactual PHP.

### [2026-09-24] pubtools.private.8x8cloud.net — deep-dive (passive/GET only)
CHOSE pubtools over vcc (less-hunted forgotten internal tool vs. most-tested eligible
login). Host is under *.8x8cloud.net = confirmed BOUNTY-ELIGIBLE wildcard.

Findings (all read-only, header'd, low-volume):
1. **App identity revealed: "Bug Scrub"** (GAS Team internal tool). Node/Express app
   (confirmed via default "Cannot GET /x" error pages on /signup, /index — both dead
   links, no GET handler).
2. **/local-login is LIVE (200)** despite being commented out of the main /login page's
   UI. Full email+password login form (POST /login) + a "Signup" link (dead: /signup
   returns Express 404). This is a real SECOND auth path (local creds) alongside Google
   OAuth — expands attack surface (weak local auth? account enumeration via login
   error differences? no rate limiting?). NOT YET TESTED — submitting to the form is
   ACTIVE testing. STOPPED for go/no-go.
3. **OAuth redirect_uri points to a DEAD domain**: /auth/google kicks off with
   redirect_uri=https://salesforce-case-status.dxi.eu/auth/google/callback
   (client_id ...mm7mc19qstra6iogo6ugv073m0ek5q2c). DNS for that exact hostname =
   NXDOMAIN (SOA only, no A/CNAME). BUT: crt.sh confirms a cert WAS issued for
   salesforce-case-status.dxi.eu historically -> it was once a real live app,
   decommissioned, and the Google OAuth client's registered redirect_uri was never
   updated. dxi.eu zone itself is still active (SOA via nameshift.com, resolves fine)
   and is 8x8's own subsidiary domain (matches "DXI (2015)" in policy + past disclosed
   axa.dxi.eu bugs #418308/#722301). VERDICT: this is an orphaned/stale OAuth config,
   NOT a classic subdomain takeover — no dangling CNAME to a third-party host exists;
   an external attacker cannot register a subdomain of a zone 8x8/DXI still controls.
   Low exploitability as-is. Worth a LOW-severity info/hygiene mention at most, folded
   into a local-login report rather than filed alone.
4. Minor: WEBROOT var leaks internal hostname tools.private.8x8cloud.net (cosmetic).
   Meta tag reveals a developer's name (minor, not actionable alone).

DECISION POINT: /local-login is the one genuinely promising, unexplored angle here —
a full local auth form on an internal tool that's normally reached only via Google
SSO. Testing it (submit login, check error behavior/enumeration, timing, rate limits)
is ACTIVE (POST requests with attacker-chosen data) -> awaiting user go/no-go.

### [2026-09-24] /local-login active probe (user said go) — RESULT: no exploitable bug
Test 1: POST /login, made-up email + wrong password -> 302 /login, 0.897s, fresh
  connect.sid + AWSALB/AWSALBCORS cookies issued. Followed redirect w/ session cookie:
  page shown is the generic Google-SSO landing (no flash/error message rendered at all).
Test 2: POST /login, malformed email ("not-an-email") + garbage password -> 302 /login,
  0.705s. IDENTICAL behavior to Test 1 (same status/location, no error differentiation).
=> No user-enumeration signal: both a well-formed-but-nonexistent email and a
  malformed email produce the same generic redirect with no visible error message.
  Timing difference (0.897 vs 0.705s, n=1 each) is not a reliable signal either way.
Test 3 (rate-limit check, 5 sequential attempts): BLOCKED by Claude Code's own safety
  classifier ("Third-Party Attack" - repeated login POSTs pattern-match brute-force
  tooling regardless of intent). Correctly declined; not routed around. Rate-limiting
  behavior on /local-login therefore UNTESTED/UNKNOWN.

VERDICT: /local-login is a real, live, undocumented auth surface (worth noting in a
report as attack-surface hygiene: an internal tool exposes a full local-credential
login path alongside SSO, with no visible link to it), but the two safe tests run
found NO exploitable bug (no enumeration, no error-based info leak). Rate-limiting
is unverified and cannot be tested further via automated repeated attempts.

## SESSION CONCLUSION (2026-09-24)
pubtools slice fully worked: app identity found (Bug Scrub/GAS Team), hidden local-auth
path found and safely probed (no bug), orphaned OAuth redirect assessed (low severity,
not exploitable takeover). No confirmed reportable vulnerability from this slice alone.
Remaining options: (1) vcc-* legacy Contactual PHP slice (still awaiting go/no-go from
earlier), (2) write up local-login + orphaned-OAuth-redirect together as a single LOW
severity "attack surface / config hygiene" report (8x8 has historically paid for this
class per report history), (3) return to authenticated-access blocker (test_access_request.md).
[2026-09-24: option 2 drafted -> findings/pubtools_bug_scrub_hygiene.md, parked pending polish.]

### [2026-09-24] vcc-* slice (Contactual PHP) — active, user said go
Reference host per policy: vcc-na30.8x8.com ("latest sw usually available" here;
policy also says ONE report accepted across all vcc-* domains as assumed single fix).

**Recon on /CM/login.php (still passive GET):**
- Full version disclosure: "Version: 12.0.0.0.20260914180030604", "Release: e20aa7e"
  (git commit hash). NOT independently reportable — policy explicitly lists "software
  version disclosure" as an out-of-scope low-impact issue.
- Dev comment in HTML: "// CWE ID 798 - can be mitigated, values came from LDAP, this
  is just a placeholder" -> pointed at login.js.
- Auth is AJAX (login.submit()), not plain form POST.

**Discovered: unauthenticated pre-auth endpoint** (called automatically by login.js
before any password is entered):
  GET /GEN/gen_check_tenant_admin.php?type=cm_login&admin=<user@tenant>
  -> XML: authorized, redirectURL, tenant, tenantType, algorithm, reason, agentIP, etc.
  Requires a persistent cookie jar across an initial self-redirect (vcc-web-apps cookie)
  to reach the real XML response — first attempts without a cookie jar loop forever.

**Behavioral tests run (synthetic values only — NOT real/guessed customer tenant names,
by design, to avoid reconnaissance against real 8x8 customers):**
- `foo@bar</tenant><injected>hax</injected>` -> tenant echoed as "barhax": tag brackets
  stripped, inner text of unknown tags kept.
- `foo@<script>alert(1)</script>` -> tenant echoed EMPTY: script tag AND its content
  both fully stripped. Looks like a deliberate, script-specific XSS filter (good sign,
  not a bug).
- `foo@bar'or'1'='1` -> tenant echoed VERBATIM including single quotes/equals signs,
  NO filtering, NO visible error, `reason=1`/`authorized=FALSE` same as any fake tenant.
  Does NOT by itself demonstrate SQLi (no error/behavioral signal) — would need blind
  (boolean/time-based) injection testing across multiple crafted requests to confirm,
  which is a materially more invasive/exploitation-adjacent class of testing.
- Numeric tenant / no-@ baseline -> normal echo, tenantType always defaults to "VCC"
  when tenant not found, reason always 1 for any nonexistent value.
- `algorithm` field empty in every test (never got a "tenant found" response) — would
  only populate for a genuinely existing tenant, which we deliberately did not hunt for.

STOPPED HERE for go/no-go: confirming true SQLi would require blind/time-based
injection probing (multiple requests, boolean or timing comparison) — explicitly the
kind of "test the actual exploitation path" step the audit brief says needs sign-off,
especially given this app's own SQLi history (#922567). Awaiting user decision.

### [2026-09-24] USER SAID GO — boolean blind SQLi test — LIKELY CONFIRMED, TESTING HALTED
Ran the minimum decisive test: 2 requests only, no timing payloads (SLEEP), no data
extraction attempted.
  admin=foo@' OR '1'='1   (universally TRUE if injected into a WHERE clause)
  admin=foo@' OR '1'='2   (universally FALSE)
RESULT:
  TRUE  -> TIMED OUT at 20000ms (curl --max-time hit, NO response received at all).
           Server-side duration unknown — may have run longer after curl gave up.
  FALSE -> completed in 10658ms with a normal-looking XML response (still much slower
           than the ~sub-1s baseline seen on non-OR payloads earlier in this session).
INTERPRETATION: dramatic TRUE-vs-FALSE timing differential (timeout vs. 10.6s, both
far above baseline) on a parameter already proven to pass SQL metacharacters through
UNFILTERED (earlier `bar'or'1'='1` test) is strong, standard evidence of the `admin`/
tenant value being concatenated unescaped into a live SQL WHERE clause. Endpoint:
  GET /GEN/gen_check_tenant_admin.php?type=cm_login&admin=<injectable>
Pre-authentication (no login/session needed at all) -> likely HIGH-CRITICAL severity,
more severe than the prior post-auth SQLi report #922567 (rated High) given no auth
required and apparent full-table-scan-scale impact (TRUE condition looks like it
matched/attempted to return the ENTIRE tenant table, causing the app to choke).

DECISION: TESTING HALTED IMMEDIATELY on this endpoint. Reasons:
1. Already caused one unintended ~20s+ hang against what appears to be a live
   production database — true server-side duration unknown, may exceed the 20s I
   measured. Any further payloads (SLEEP-based timing confirmation, UNION extraction,
   heavier boolean probes) risk real additional load/disruption on production
   infrastructure — crosses into the explicitly-prohibited "activity that could
   disrupt service" territory.
2. Evidence already sufficient to report without further confirmation: proven
   unfiltered special-character passthrough + reproducible dramatic timing
   differential between TRUE/FALSE boolean conditions.
3. NOT attempting: SLEEP()-based timing payloads, UNION-based data extraction, any
   payload targeting real customer data. This is a CONFIRM-AND-STOP situation, not
   confirm-and-exploit.

NEXT: write up as findings/vcc_tenant_check_sqli.md — HIGH PRIORITY, supersedes the
pubtools draft for submission order. Must include an honest note to 8x8 that a single
test inadvertently caused a ~20s response delay, in case it shows in their logs/APM.

### [2026-09-24] SQLi report SUBMITTED then CLOSED — Duplicate (#3486990)
Result: "we have already received a prior report of this vulnerability." No bounty
(standard first-to-report-only policy). IMPORTANT: this CONFIRMS the vulnerability was
real — 8x8 explicitly referenced it as "this vulnerability," not a dismissal/informative
close. Validates the boolean-timing-differential methodology and the decision to stop
before data extraction; the earlier concern that this could've been a WAF artifact or
LDAP-related false positive did not pan out — it was a genuine, previously-known bug.
Lesson: gen_check_tenant_admin.php is reachable via a discoverable client-side JS file
(login.js) that any hunter doing basic recon would also pull — not a deeply hidden
find, so convergence with another reporter isn't surprising on a high-volume program
(~7 reports/day). No further action on this endpoint; move on.

### [2026-09-24] Continued hunting — password-reset flow + sibling endpoint
Found via login.js reference: CM/admin_forgot_password.php (200, real form: uName ->
tenant/admin split, POSTs back to itself with reset=reset). Hardcoded server-response
states in the HTML: "incorrect admin/tenant", "invalid reset link", "temporarily
locked", "permanently locked", "processing error" — differentiated lockout messages
are a classic enumeration vector, matching our own threat-model invariant on account
recovery. NOT tested by submitting the actual POST (reset=reset) — even with a fake
uName, this action plausibly triggers a real reset email server-side if it happens to
match a real account structurally; not worth that risk for a fake-input test.

Pulled admin_forgot_password.js -> reveals a SIBLING pre-check endpoint:
  GET /GEN/gen_check_redirection.php?tenant=<t>&admin=<a>
Same tenant/admin params as the CONFIRMED-vulnerable gen_check_tenant_admin.php, same
GEN/ directory -> likely shares backend tenant-lookup code, meaning a fresh SQLi
finding here would likely ALSO close as duplicate of the same root cause.
Ran ONE safe test only (baseline fake tenant vs. single-quote value, no OR/boolean
payload): both ~0.68-0.69s, IDENTICAL response shape, no reflection of the tenant
value in the response at all (unlike the other endpoint). Inconclusive on SQLi (can't
rule in/out without repeating the risky boolean-timing technique against what's likely
the same already-reported codebase issue) — deliberately NOT repeating that test here.
VERDICT: low-priority, not worth further risk for likely-duplicate value. Noted, moving on.

NEXT: pivot to AGUI/login.php (Contact Center Agent Workspace) — a genuinely separate
application from Configuration Manager per the program's own product breakdown, not
yet examined at all beyond confirming it returns 200.

### [2026-09-24] AGUI/login.php deep-dive
Full page + JS pulled: AGUI/js/login.js, AGUI/js/login_shared.js. Findings:
- Hardcoded client-side Grafana telemetry key (grafanaFeApiKey) shipped pre-auth ->
  matches 8x8's OWN explicit policy exclusion ("client-side API keys... only accepted
  if you show both abuse AND improved handling"). Standard RUM/telemetry-ingestion key
  pattern (like a Sentry DSN) — demonstrating real abuse would need visibility into
  internal dashboards I don't have. NOT pursued further; logged only.
- isSafeLoginRedirectURL() found in login_shared.js — a same-origin check with a
  comment explicitly referencing "tampered IndexedDB cache entries" as an attack
  vector. Reads as an ALREADY-PATCHED open-redirect fix. Not worth probing (hardened).
- New sibling endpoints found via code reading: gen_check_tenant_agent.php (AGUI login
  check), gen_check_tenant.php (SSO check), gen_send_lock_mail.php (sends a real email
  to admins on agent lockout — NOT tested at all, calling it risks sending an actual
  email, which is prohibited testing conduct regardless of how synthetic the input is).

**Enumeration hypothesis — TESTED AND DISPROVEN.** Client-side code in
checkTenantResponse() branches error messages on a `uidsMatch` field when reason=1,
which looked like a strong pre-auth enumeration vector (differentiates "exists" vs
"invalid creds"). Tested gen_check_tenant_agent.php with 6 synthetic tenant/agent
combos: uidsmatch=true for EVERY non-empty tenant value tested (regardless of how
obviously fake), only flipping to false when tenant was literally empty. This is
consistent with a basic input-presence check, NOT a real existence/enumeration signal.
Correctly did NOT write this up — hypothesis failed live testing before any report was
drafted. Good discipline moment: reading code can suggest a vuln, but only testing
confirms or kills it.

STATUS CHECK: vcc-* Configuration Manager + AGUI both now reasonably well-explored
(3 sibling GEN/*.php endpoints examined, 1 confirmed-real bug found [now duplicate],
2 dead ends). Diminishing returns setting in on this specific app family. Decision
point for user: keep digging deeper (common.js, the rtapi/jabbind3.php real-time
protocol used post-login — bigger investment, needs valid creds to go far) or
consider this slice adequately covered and move to a different area of 8x8's scope.
