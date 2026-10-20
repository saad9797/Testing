# Scope Lock — Abercrombie & Fitch Bug Bounty (HackerOne: abercrombie_fitch_bbp)

Source: https://hackerone.com/abercrombie_fitch_bbp (policy) and /policy_scopes (scope table), read live 2026-09-27.

## In-scope assets (bounty-eligible, Critical max severity on all)

| Asset | Type | Resolved reports (share) |
|---|---|---|
| abercrombie.com | Domain | 23 (36%) |
| anfcorp.com | Domain | 15 (23%) |
| hollisterco.com | Domain | 8 (13%) |
| corporate.abercrombie.com | Domain | 2 (3%) |
| com.abercrombie.hollister | Android: Play Store | 1 (2%) |
| com.abercrombie.abercrombie | Android: Play Store | 1 (2%) |
| iOS app 383915209 | iOS: App Store | 0 |
| iOS app 339041767 | iOS: App Store | 0 |

**This engagement targets the web domains only** (abercrombie.com, hollisterco.com, corporate.abercrombie.com, anfcorp.com). Mobile apps noted but out of current effort.

## Explicitly OUT of scope (do not touch)

- `nonmerchvendorprofile.anfcorp.com`
- `applications.abercrombie.com/`

## Rewards (90-day avg, current bounty table)

| Severity | Base | 90-day avg |
|---|---|---|
| Low | $250 | $250 (25% of paid reports) |
| Medium | $750 | $750 (35.94%) |
| High | $2,500 | $2,600 (17.19%) |
| Critical | $4,000 | $2,250 (21.88%) |

## Excluded vulnerability classes (do not spend time here)

Clickjacking w/o sensitive action, CSRF on unauth/non-sensitive forms, MITM/physical-access-required attacks, known-vuln libraries w/o working PoC, CSV injection w/o demonstrated impact, SSL/TLS best-practice gaps, DoS, content spoofing/text injection w/o vector, rate-limiting/bruteforce/enumeration on non-auth endpoints, CSP best-practice gaps, email SPF/DKIM/DMARC gaps, outdated-browser-only issues, version disclosure/banner/stack-trace w/o PoC (informational only), recent (<1mo) patched zero-days (case-by-case), tabnabbing/typosquatting, open redirect w/o extra impact, issues requiring unlikely user interaction/phishing, **promotional/discount code abuse**, social engineering of customer service (voice or chat).

## Mandatory / recommended identification

- No mandatory header found in policy (no "X-HackerOne-Username must be set on every request" clause, unlike some programs). **Recommended, not mandatory**: use a modified User-Agent or embed `h1:<hackerone-username>` in PoC artifacts so A&F's team can identify verified-researcher traffic.
- No explicit numeric scanner rate limit is published (contrast: Vercel's program states 5 QPS explicitly; A&F's does not). Given the absence of a stated limit, default to conservative, human-paced, low-volume requests — do not run high-volume automated scanning. The site also runs active fraud/bot-detection infra (Signifyd `dp.signifyd.com/fp-web`, a `_fs-ch-*/check-detection` challenge endpoint, FullStory session replay, Dynatrace RUM) — aggressive automated traffic risks bot-mitigation blocks and possible test-account flags, independent of program rules.

## Program rules (verbatim summary)

- Closed scope — only listed assets count.
- No credentials provided; self-register test accounts with a `you@wearehackerone.com`-style alias email. **(Done — user has registered.)**
- One vulnerability per report unless chaining is required for impact; root-cause dedup applies (one bounty per underlying issue).
- Duplicates: first fully-reproducible report wins.
- **PII exfiltration/exposure is expressly prohibited** — if a vector could expose another real customer's PII, use your own test account(s) for the PoC, never pull real customer data.
- If credentials are found exposed, do not use them to access underlying systems — report the source instead.
- Social engineering (incl. voice/chat with customer service) is prohibited.
- A&F/Hollister corporate employees/contractors ineligible to participate.
- Abercrombie and Hollister share the same underlying architecture — do not file duplicate reports for the same root cause found on both domains.

## Response SLAs

First response: 2 business days · Triage: 2 business days · Time to bounty: 14 business days · Response efficiency: 86%.

## Disclosure

Standard HackerOne disclosure guidelines; do not discuss the program or any vulnerability (even resolved) outside the program without written consent.

## Test account

Self-registered by user on abercrombie.com/hollisterco.com with a wearehackerone.com alias email (per program instructions). Credentials held by user only — not shared into this session.

## Current phase

Unauthenticated recon only (Phases 0–2). Authenticated mutation/differential testing (Phase 3+) deferred until user is set up with Burp Suite as proxy, per user's explicit sequencing decision.
