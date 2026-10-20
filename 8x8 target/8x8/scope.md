# 8x8 Bug Bounty — Program Policy & Scope

Source: https://hackerone.com/8x8-bounty (public, no login required)
Captured: 2026-09-15 via automated browser. Policy last updated May 16, 2026;
scope last updated Aug 31, 2026; rewards last updated Sept 15, 2026.
Authoritative structured scope saved at `recon/scope_official.csv` (138 rows).

> ⚠️ This is captured from the PUBLIC program view. If you have a HackerOne
> account, re-check the signed-in view before submitting — some programs show
> additional detail once authenticated. Re-verify before every session.

---

## ‼️ MANDATORY RULES (these gate all tooling — read first)

1. **Every HTTP request** you send (manually or via any tool) must include your
   HackerOne username appended to the `User-Agent`, in this header form:
   ```
   X-HackerOne: <your-h1-username>
   ```
2. Use your **`<your-h1-username>@wearehackerone.com`** email alias when creating
   accounts / entering data in the applications.
3. **Do NOT conduct automated or high-volume testing without prior coordination.**
   → subfinder (passive) is fine. httpx at low rate is fine. Aggressive ffuf
   content-discovery / brute-forcing counts as high-volume — throttle hard or ask
   the program first. No DoS/DDoS.
4. Only interact with accounts you own or have explicit permission for.
5. No social engineering / phishing of 8x8 staff; no physical attacks.
6. `connect.8x8.com` support functionality: put "HackerOne" in the subject line
   and keep requests to an absolute minimum.

---

## Program facts (as of 2026-09-15)

- Bounty launched: **Jan 2023** (paid program is ~3.5 yrs old)
- Total bounties paid: **$488,735** | Average bounty: **$500** | Top range: **$1,337–$3,000**
- Reports received (90 days): **621** (~7/day — busy, competitive)
- Reports resolved: **1,295** | Hackers thanked: **694** | Assets in scope: 115
- Response efficiency: 100% | First response: ~1 hr | Triage: ~3 hr | Bounty: ~1.5 days
- Gold Standard Safe Harbor | Fast Payment (within 1 month) | Closed Scope | Includes retesting & collaboration

### Rewards by severity
| Severity | Range | 90-day avg | % of submissions |
|---|---|---|---|
| Low | $50 | $95 | 24.63% |
| Medium | $100–$250 | $500 | 40.42% |
| High | $250–$500 | $1,152 | 28.46% |
| Critical | $500–$1,000 | $2,286 | 6.49% |
| "Intellectual Property on Public Domains" asset | Low $50 / Med $100 / High $250 / Crit $500 | | |

---

## Policy (verbatim, Program guidelines page)

**Overview:** "At 8x8, we help companies get their employees, customers and
applications talking to make people more connected and productive no matter where
they are in the world. At 8x8 we value security and recognize the importance of
ensuring the integrity and confidentiality of global communications."

**Product scope (products, not all bounty-eligible — see Scope tables below):**
- **8x8 Work** — Web: https://work.8x8.com/ ; Desktop; iOS; Android. ⚠️ No test creds provided.
- **8x8 Virtual Contact Center (VCC)** — `vcc-*.8x8.com/CM/` (Config Mgr),
  `vcc-*.8x8.com/AGUI/` (Agent Workspace), `vcc-*.8x8.com/QM/` (Quality Mgmt),
  https://superx.8x8.com/ (Supervisor), `analytics-*.8x8.com`. Latest sw usually
  on https://vcc-na30.8x8.com/. ⚠️ One unique report accepted across all related
  domains (assumed single fix). ⚠️ For Burp proxying of Agent Workspace, add
  streaming exception for `jabbind3.php`.
- **Jitsi** — Infra: `*.jitsi.net`, `*.jit.si`; Source: https://github.com/jitsi.
  ⚠️ PoC must be on meet.jit.si, 8x8.vc, or a self-hosted deployment. Code-only
  vulns w/o production PoC = lower severity. Dev-config-only vulns
  (e.g. `BYPASS_AUTHORIZATION=1`) = lower severity. Many jitsi repos out of scope
  (archived/experimental/forks — see policy page for full list).
- **8x8 Video Conferencing** — https://8x8.vc/
- **Jitsi as a Service (JaaS)** — self-signup https://jaas.8x8.vc/
- **8x8 Connect (CPaaS)** — self-signup https://connect.8x8.com/ ; APIs:
  sms.8x8.com, sms.8x8.uk, sms.8x8.id, sms.us.8x8.com, chatapps.8x8.com, …

**Response Targets:** first response 1 business day; triage 2 business days.

**Disclosure Policy:** report promptly; do not discuss outside the program without
8x8's consent; avoid privacy violations / data destruction / service disruption;
only interact with accounts you own; follow HackerOne disclosure guidelines.

**Testing Identification:** use `[username]@wearehackerone.com` alias; append
`X-HackerOne: [H1 username]` to the User-Agent on every request.

**"If You See Something, Say Something"** = Responsible Disclosure assets. Vulns
on these are IN SCOPE for submission but **NOT eligible for bounties**.

**8x8 subsidiaries/acquisitions referenced:** Callroute (2026), Maven Lab (2026),
In2Tel (2025), Fuze (2022), Wavecell (2019), Jitsi (2018), QSC (2015),
MarianaIQ (2015), DXI (2015), Voicenet (2013), Contactual (2011).

---

## Scope — OUT / Ineligible findings (verbatim)

**Core ineligible findings** are out of scope (HackerOne standard list), plus:
- **IDORs with unpredictable IDs** — IDORs with unguessable/non-enumerable
  identifiers (UUIDs) are OUT.
- **0-day vulnerabilities** — public 0-days patched < 1 month: case-by-case.
- **Credential Stuffing** — 🚨 strictly prohibited; OUT; not rewarded.
- **Client-Side API Keys** — keys intentionally client-accessible (Google Maps,
  Analytics, …) only accepted if you show BOTH abuse AND how handling can improve.

**Testing Conduct — do NOT:** automated/high-volume testing without coordination;
DoS/DDoS; spam; social engineering/phishing of staff; physical attacks.

**Common low-impact issues (OUT):** missing security headers (HSTS, CSP, SPF,
DMARC, X-Frame-Options); missing cookie flags without exploit; SSL/TLS config
issues (weak ciphers, BEAST/CRIME, etc.); version/banner disclosure & verbose
errors; clickjacking on non-sensitive pages; Self-XSS w/o further impact; CSRF on
unauthenticated / non-sensitive forms; CSV injection w/o impact; tab-nabbing.

**Auth & access control (OUT):** credential stuffing; rate-limiting/brute-force
without demonstrated account compromise; issues requiring MITM or physical device
access.

**Dependencies & browsers (OUT):** vulnerable libs without a working PoC in 8x8's
context; issues only on browsers >2 stable versions behind.

**Mobile-specific (OUT):** findings needing a malicious app installed on victim's
device; same-device cross-app attacks (intents, IPC, overlays, accessibility);
task hijacking (StrandHogg); insecure storage on rooted/jailbroken devices; issues
needing local code execution in another app's context.

**Scanner findings (OUT):** low-severity automated-scanner output without
demonstrated impact / exploitation path.

**Target-specific — `connect.8x8.com`:** IDORs with UUIDs OUT; IDORs based on
`AccountId` / `subAccountId` OUT. Temporary scope exclusion: `campaign.wavecell.com`,
`contacts.8x8.com` (and regional equivalents).

**Target-specific — Salesforce portals (`8x8.my.site.com`, Partner Portal):**
UUID-based IDORs OUT; for Partner Portal, disclosure of non-sensitive info
(Name, City, …) and non-sensitive ContentDocument (marketing collateral) OUT.

---

## Scope — IN & BOUNTY-ELIGIBLE (21 assets — where money is)

Full table in `recon/scope_official.csv`. Resolved-report counts (activity) from
the scope page in parentheses.

**Core product web apps (URL):**
- work.8x8.com (5) — 8x8 Work for Web. No test creds.
- user-profile.8x8.com (4)
- sso.8x8.com (19) — SSO. ⚠️ MFA-bypass needing prior credential knowledge = MEDIUM only.
- platform.8x8.com (0)
- apps.8x8.com (0) — Application Panel
- admin.8x8.com (11) — admin portal (users + telephony)
- pay.8x8.com (2)
- https://webrtc.8x8.com/ (0)

**Staging/pilot (also eligible):**
- work-staging.8x8.com (0)
- user-profile-staging.8x8.com (0)
- platform.8x8pilot.com (0)
- uc.8x8pilot.com (0)
- sso.8x8pilot.com (1) — same MFA note as sso.8x8.com

**Wildcards (eligible — broad surface, best for enumeration):**
- vcc-*.8x8.com (**93** — most active eligible target; VCC contact center)
- *.chalet.8x8.com and https://*.chalet.8x8.com/ws/v1 (2) — 8x8 Chat
- *.wavecell.com (—)
- *.8x8cloud.net (—)
- *.p8t.us (—)
- http://*.packet8.net (—)

**Other (eligible):**
- **Intellectual Property on Public Domains (29)** — leaks in public domains
  (GitHub, pastebin, etc.) containing sensitive/proprietary info. Pure OSINT.

## Scope — IN but BOUNTY-INELIGIBLE (testable, NO pay — 117 assets)

Do not spend first-bounty effort here. Includes: 8x8.my.site.com + Partner Portal
(Salesforce), connect.8x8.com, api.8x8.com, voapi/vap/map/mcp/maestro/bridge/
dashboard.qa/cloud8/vcc-ce.8x8.com, callroute.com/.io, sipsynergy.co.uk, all
*.jitsi.net / *.jit.si / 8x8.vc, all ASN/IP ranges, "Cloud Misconfigurations",
mobile apps, and more. Full list: `recon/scope_official.csv` (eligible_for_bounty=false).

---

## Safe Harbor (Gold Standard, verbatim)

"Gold Standard Safe Harbor supports the protection of organizations and hackers
engaged in Good Faith Security Research. 'Good Faith Security Research' is
accessing a computer solely for purposes of good-faith testing, investigation,
and/or correction of a security flaw or vulnerability, where such activity is
carried out in a manner designed to avoid any harm to individuals or the public,
and where the information derived from the activity is used primarily to promote
the security or safety of the class of devices, machines, or online services to
which the accessed computer belongs, or those who use such devices, machines, or
online services."

"We consider Good Faith Security Research to be authorized activity that is
protected from adversarial legal action by us. We waive any relevant restriction
in our Terms of Service ('TOS') and/or Acceptable Use Policies ('AUP') that
conflicts with the standard for Good Faith Security Research outlined here."

This means that, for activity conducted while this program is active, we:
- **Will not** bring legal action against you or report you for Good Faith
  Security Research, including for bypassing technological measures we use to
  protect the applications in scope; and,
- **Will** take steps to make known that you conducted Good Faith Security
  Research if someone else brings legal action against you.

"You should contact us for clarification before engaging in conduct that you think
may be inconsistent with Good Faith Security Research or unaddressed by our policy.
Keep in mind that we are not able to authorize security research on third-party
infrastructure, and a third party is not bound by this safe harbor statement."
