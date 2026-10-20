# 8x8 — Threat Model (black-box, remote)

> Engagement type: **black-box remote web** bug bounty (HackerOne `8x8-bounty`).
> We do NOT have source code. Everything below is inferred from public data: the
> program scope, 26 publicly disclosed reports, and CVEs in the open-source
> components 8x8 is known to run. Confirm each assumption against the live target.
>
> Last updated: 2026-09-15 | Confirmed findings: none yet (audit just started)

---

## ⚠️ CORRECTIONS after reading the real scope (2026-09-15)

The authoritative policy/scope (now in `scope.md` + `recon/scope_official.csv`)
overrides several assumptions below:

1. **Only 21 of 138 scope entries are bounty-eligible.** Everything else is
   testable under safe harbor but pays $0. Slice priorities below must be
   re-read against the eligible list in `scope.md`.
2. **Salesforce slice (`8x8.my.site.com`) is bounty-INELIGIBLE.** The old "Slice 2"
   below is a $0 target — demote it. (Still submittable for goodwill, no pay.)
3. **Jitsi is IN scope but bounty-INELIGIBLE** (`*.jitsi.net`, `*.jit.si`, `8x8.vc`).
   Old "Slice 6" pays nothing — demote.
4. **Fuze is NOT in current scope** (my day-old cache was stale). Do not test fuze.
   `callroute.*` IS in scope but INELIGIBLE.
5. **IDOR is heavily carved out:** UUID/non-enumerable IDORs are OUT everywhere;
   on `connect.8x8.com`, `AccountId`/`subAccountId` IDORs are also OUT (and
   connect.8x8.com is ineligible anyway). IDOR only pays on eligible assets with
   *enumerable/predictable* IDs (e.g. user-profile.8x8.com).
6. **"Automated/high-volume testing without coordination" is prohibited**, and
   **every request needs `X-HackerOne: <user>` in the UA** + `@wearehackerone.com`
   alias. This constrains the recon tooling — see `scope.md`.
7. Program is far busier than "26 disclosed" implied: **1,295 resolved, 621
   reports/90 days.** Competitive — favor eligible wildcards & OSINT over the
   picked-over core apps.

### Revised eligible-target priority (for a first PAID bounty)
- **A. Intellectual Property on Public Domains (OSINT):** leaked 8x8 secrets/creds
  on GitHub/pastebin. Eligible, 29 resolved, no live-target requests, lowest risk
  of tripping the "high-volume" rule. Best beginner ROI now.
- **B. Eligible wildcards:** `vcc-*.8x8.com` (93 resolved), `*.wavecell.com`,
  `*.8x8cloud.net`, `*.p8t.us`, `*.packet8.net`, `*.chalet.8x8.com` — passive
  subdomain enumeration → find forgotten hosts → exposed-info / takeover.
- **C. Eligible staging:** `work-staging`, `user-profile-staging`,
  `*.8x8pilot.com` — less-hardened than prod, still pay.
- **D. Core apps** (`work`, `user-profile`, `sso`, `admin`, `pay`): pay well but
  picked over; go here for logic/IDOR only after A–C.

---

## Crown jewels (what an attacker actually wants here)

8x8 is a UCaaS/CCaaS/CPaaS provider — business phone, video meetings, contact
center, and communications APIs (SMS/voice). The valuable targets:

1. **Cross-tenant data access** — one customer org reading another org's calls,
   messages, contacts, recordings, or admin config. (Multi-tenancy is the #1
   crown jewel for any B2B SaaS.)
2. **Account/session takeover** — of another user, especially an org admin.
3. **Communications abuse** — sending SMS/calls/emails through a victim's account
   or 8x8's own infra (spam/phishing from a trusted domain — report #840688 was
   exactly this).
4. **Internal/infra exposure** — admin panels, dashboards, source, credentials
   reachable from the internet (a recurring theme in disclosed reports).

## Attacker models in scope for this engagement

| # | Attacker | Applies? | Why |
|---|----------|----------|-----|
| A1 | Remote **unauthenticated** | ✅ primary | Public web assets, login/recovery flows, Salesforce guest user, subdomain takeover, exposed panels |
| A2 | Remote **authenticated, low-priv** (free/trial tenant you create) | ✅ primary | IDOR, cross-tenant, privilege escalation — you can self-register test accounts |
| A3 | **Cross-tenant** (two orgs you control) | ✅ primary | The highest-value class; needs two test tenants |
| A4 | Malicious meeting participant → other participant | ✅ (Jitsi-derived) | The Jitsi CVEs (44080/44081) are participant→participant |
| A5 | Insider / employee / physical | ❌ out | Program forbids testing employees / social engineering |

**Every finding must be reachable by A1–A4.** Discard anything needing insider
access, a leaked employee credential, or physical access.

---

## Trust boundaries

- **browser ↔ 8x8 app servers** (main product web apps)
- **tenant ↔ tenant** (your org's data vs. another org's) — the boundary that pays
- **unauthenticated guest ↔ Salesforce data** (`8x8.my.site.com` Experience Cloud)
- **meeting participant ↔ participant** (Jitsi-based video)
- **acquired product ↔ core 8x8 identity** (fuze.me, callroute.*, wavecell-derived —
  may not fully share 8x8's SSO/session model = seam)
- **staging/QA ↔ production** (does a QA host share prod data or creds?)

---

## Invariants (things that MUST hold — each is a bug if violated)

Auth / session:
- [ ] A password/2FA change must require the *current* credential, server-side
      (report #893085: 2FA was disabled via **response tampering** — client-trusted).
- [ ] Session tokens must be bound to their origin/tenant and not replayable across
      acquired-product domains.
- [ ] Account recovery must not leak whether an account exists, and reset tokens
      must be single-use, expiring, and unguessable.

Authorization / tenancy:
- [ ] A user may only read/write objects belonging to their own tenant.
- [ ] Object references (contact IDs, user IDs, group IDs) must be authorized
      server-side, not just hidden in the UI (report #879960 was an IDOR on contacts).
- [ ] The Salesforce guest user on `8x8.my.site.com` must NOT be able to query
      arbitrary objects/records (Aura/GraphQL guest-access class — see notes).

Input handling:
- [ ] All user-controlled output must be contextually encoded (huge XSS history:
      stored #413077, reflected #503988/#770513/#722301, DOM #895917, generic #418248).
- [ ] Redirect targets must be validated against an allowlist (open redirect #929633).
- [ ] Headers built from user input must strip CR/LF (CRLF injection #413115).

Infra / exposure:
- [ ] No admin panel, dashboard, actuator, or source repo may be reachable
      unauthenticated (exposed k8s dashboard #1418101, Spring Boot Admin default
      creds #954818, exposed .svn #710368, phpinfo #907701, exposed PHP deps #1132457).
- [ ] Every DNS record pointing at a deprovisioned service must be removed
      (subdomain takeover #1181762, #1280167 — both on acquired wavecell infra).

---

## Historical bug-class frequency (from 26 disclosed reports)

Ordered by how often 8x8 has *accepted and paid* this class — this is your
priority list, because "accepted here before" is the strongest signal of "will
be accepted again":

1. **Information disclosure / exposed infra** (≈8 reports) — exposed dashboards,
   default creds, .svn/.git, phpinfo, directory listing, hardcoded creds in APK.
   Pure recon. **Highest ROI for a beginner.**
2. **XSS** (≈7 reports) — stored, reflected, DOM. Broad surface, many subdomains.
3. **Subdomain takeover** (≈2, both on acquired domains) — pure recon, no exploit dev.
4. **Auth bypass / broken auth** (≈3) — Jitsi JWT bypass, Tomcat misconfig, 2FA
   response tampering.
5. **IDOR** (≈1 disclosed, but the class is under-reported — dig here).
6. **Injection** (SQLi #922567, command injection #807961, CRLF #413115) — higher
   skill, higher payout.

## OSS components 8x8 runs → known-CVE bug classes to look for

- **Jitsi Meet** (video): CVE-2024-44080 / -44081 (arbitrary-URL load / SSRF-ish via
  giphy & video-share, participant→participant); CVE-2021-39205 (client XSS via JSON
  property injection). → Check the deployed Jitsi version; test participant→participant
  URL-load and JSON-injection XSS if version is behind.
- **Salesforce Experience Cloud** (`8x8.my.site.com`): the live 2025–26 guest-user
  misconfig class — unauthenticated Aura/GraphQL access can dump CRM objects
  (names, PII) when guest permissions are overly permissive. → Run Aura endpoint
  enumeration against the guest user. This is a *current, mass-exploited* class and
  8x8 runs a my.site.com portal.
- **Apache Tomcat / Spring Boot** (seen in #1364022, #954818): default consoles,
  actuator endpoints, manager app. → Probe for `/manager`, `/actuator/*`.

---

## Prioritized attack-surface slices (audit order, with justification)

**Slice 1 — Exposed infra / info disclosure on the acquisition + staging domains.**
Why first: most-accepted class here, pure recon (no exploit dev), and the
acquisition domains (fuze.me, callroute.*, wavecell-derived) + staging hosts
(work-staging, dashboard.qa.ai, user-profile-staging) are the least-hardened part
of an otherwise old, picked-over program. Best beginner ROI.

**Slice 2 — Salesforce guest-user exposure on `8x8.my.site.com`.**
Why: a specific, current, high-severity class with a known methodology (Aura/GraphQL
guest enumeration), and it's unauthenticated (A1). One misconfigured object = real
PII impact = real payout.

**Slice 3 — Subdomain takeover across the full resolved subdomain set.**
Why: 8x8 has paid this twice on acquired infra; acquisitions create dangling DNS.
Pure recon (subfinder → dnsx → subzy). Low effort, sometimes High severity.

**Slice 4 — IDOR / cross-tenant on user-profile & contact/group APIs (A2/A3).**
Why: under-reported relative to how much B2B surface exists; needs two test tenants
but that's cheap; `user-profile.8x8.com` name alone screams per-user object access.

**Slice 5 — XSS across the many secondary web apps.**
Why: broadest historical class, but the obvious spots are picked over — target the
acquired/secondary apps' input fields, not the core product.

**Slice 6 — Jitsi video slice (A4).**
Why: real CVE history, but requires the deployed version to be behind and two
participants — do this once you've confirmed the version.

---

## What "validate the finding" means in THIS engagement

We can't build 8x8 locally or run their test suite. A validated finding here =
a **reproducible request/response captured against the live target**, saved to
`requests/`, showing the invariant broken — e.g. two saved responses proving
account B's data returned to account A. The user sends every live request (within
`scope.md` rules); Claude Code reasons over the saved artifacts to confirm impact
and draft the report. No active exploitation is fired from the Claude Code session.
