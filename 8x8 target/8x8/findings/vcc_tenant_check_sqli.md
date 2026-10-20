# [Draft] Pre-authentication SQL Injection in gen_check_tenant_admin.php (vcc-* Configuration Manager)

STATUS: draft, HIGH PRIORITY — testing intentionally halted after minimum confirmatory
evidence to avoid further production impact. Needs your review of the honesty note
below before submission, and ideally one careful confirmation pass by you (or 8x8's
own triage) rather than more automated testing from here.

## Summary
The `admin` parameter of the unauthenticated endpoint `/GEN/gen_check_tenant_admin.php`
(called automatically by the Configuration Manager login page, before any credentials
are submitted) is concatenated into a backend query without sanitization or
parameterization. A boolean-based blind test shows a dramatic timing differential
between a universally-true and a universally-false injected condition, consistent with
the payload reaching a live SQL `WHERE` clause and, in the TRUE case, matching/scanning
what appears to be the full tenant table.

This requires **no authentication** — it's reachable by anyone who can load the login
page, before entering any username or password.

## Severity (estimate)
**High–Critical.** Pre-auth SQLi against what is very likely the primary customer/tenant
table of an enterprise contact-center product. 8x8 has previously paid a **High**
severity bounty for a *post-authentication* SQLi in this same product family
(#922567 — stacked queries in "export to Excel"). This finding requires no
authentication at all, which is typically assessed as more severe, and the apparent
scale of data touched (looks like the entire tenant table, not a single row) raises
the potential impact further — full read (and potentially write, if stacked
queries are possible as they were in #922567) access to tenant/customer data would be
Critical impact.

**This severity estimate is based on strong circumstantial evidence (timing
differential + unfiltered special characters), not on extracted data** — testing was
deliberately stopped before confirming exploitability further. 8x8's own triage should
verify server-side.

## Affected asset
`vcc-na30.8x8.com` (policy explicitly names this as the reference/"latest software"
instance; per program policy, one report is accepted across all `vcc-*.8x8.com`
domains as an assumed single fix — do not need to test every instance).

Endpoint: `GET /GEN/gen_check_tenant_admin.php?type=cm_login&admin=<value>`

## Steps to reproduce
**Prerequisite:** the endpoint issues a redirect-with-cookie on first contact
(`vcc-web-apps` cookie); a client must retain cookies across this redirect to reach
the real XML response (a plain `curl` without a cookie jar will appear to loop/return
only a stub HTML redirect page).

1. Establish a cookie jar by requesting `https://vcc-na30.8x8.com/CM/login.php` once.
2. Confirm unfiltered special characters reach the backend — request:
   ```
   GET /GEN/gen_check_tenant_admin.php?type=cm_login&admin=foo@bar'or'1'='1
   ```
   Response echoes the tenant value verbatim, including unescaped quotes:
   `<tenant>bar'or'1'='1</tenant>`, with `authorized=FALSE`, `reason=1` — same shape
   as any ordinary nonexistent tenant, i.e. no input validation/escaping occurring.
3. Boolean-differential test — two requests, same session/cookie jar:
   ```
   A) admin=foo@' OR '1'='1     (condition always TRUE)
   B) admin=foo@' OR '1'='2     (condition always FALSE)
   ```
   Observed:
   - (A) TRUE: no response within 20 seconds (client timeout reached; true
     server-side duration unknown and may be longer).
   - (B) FALSE: response returned in ~10.7 seconds — still far above the
     sub-1-second baseline observed for ordinary (non-injected) values.

   This TRUE-vs-FALSE differential, on a parameter already shown to pass SQL
   metacharacters through unfiltered, is the standard signature of boolean-based blind
   SQL injection: the TRUE condition causes the query to match/process far more rows
   (likely the entire tenant table) than intended, while FALSE causes a smaller but
   still abnormal delay (possibly still evaluating the injected clause per row).

## Proof of concept
Raw request/response pairs to be saved to `../requests/vcc_sqli_*` before submission
(timing evidence, cookie-jar requirement, and the three test cases above).

## Impact
If confirmed by 8x8: an unauthenticated attacker could potentially:
- Enumerate or extract tenant/customer records from the underlying database via
  further blind or (if error messages/UNION are viable) direct extraction techniques.
- Depending on DB permissions and query context, potentially write/modify data if
  stacked queries are possible (as demonstrated in the related historical report
  #922567 on this same product).
- All without any login, from the public internet.

## ⚠️ Important disclosure note for the report
While confirming this, a single boolean-TRUE test request caused the server to hang
for at least 20 seconds without responding (client-side timeout; actual duration
server-side is unknown and may have been longer). No further payloads were sent after
observing this in order to avoid additional load on what appears to be a production
system. **This should be disclosed transparently in the submitted report** — 8x8's
security/ops team may see this exact slow request in their logs or APM around the
timestamp of testing, and being upfront about it (rather than omitting it) is both the
right thing to do and pre-empts any confusion if they investigate independently.

## Suggested fix
- Parameterize the query backing `gen_check_tenant_admin.php` (prepared statements /
  bound parameters) rather than string-concatenating the `admin`/tenant value.
- Apply the same input validation used elsewhere in this app (the endpoint already
  demonstrates a working script-tag filter — extend equivalent rigor to SQL
  metacharacters, in addition to fixing the root cause via parameterization).

## Evidence files
TODO before submission: save the three raw request/response transcripts (with
timestamps) into `../requests/`.

## Recommendation before submitting
Given the severity and the production-impact risk already observed, consider:
1. Submitting this to 8x8 now with the evidence as-is (timing differential + unfiltered
   passthrough) rather than doing further confirmation testing yourself — let their
   triage team verify server-side, where they have safe, non-production ways to do so.
2. NOT running any additional SQLi payloads against this endpoint from this workspace.
