# Known Scope (pulled from public HackerOne scope data, 2026-09-14)

Cross-check every one of these against `../scope.md` once you've pasted the real policy —
this list is a starting point for recon, not a substitute for the live scope page.

## Core / high-attention (likely already hardened — lower priority to re-test blind)
- 8x8.com
- app.8x8.com
- api.8x8.com
- platform.8x8.com

## Acquisition-derived (prioritize — newer/merged infra, historically buggy here)
- fuze.me
- www.fuzemeeting.com
- callroute.com
- callroute.io
- (anything resolving under a wavecell-descended domain, if still present)

## Staging / QA / debug / internal-sounding (prioritize)
- dashboard.qa.ai.8x8.com
- work-staging.8x8.com
- work.8x8.com
- user-profile-staging.8x8.com
- user-profile.8x8.com
- debug.8x8.com
- admin.8x8.com
- admin-resolve.8x8.com
- sso.8x8.com
- sso.8x8pilot.com
- platform.8x8pilot.com
- uc.8x8pilot.com
- unreal-agents.8x8pilot.com
- pubtools.private.8x8cloud.net
- maestro.8x8.cloud
- vap.8x8.com
- voapi.8x8.com

## Portals / secondary apps
- community.8x8.com
- developer.8x8.com
- support-portal.8x8.com
- connect.8x8.com
- converse.8x8.com
- bridge.8x8.com
- resolve.8x8.com
- vcc-ce.8x8.com
- video-agent.8x8.com
- map.8x8.com
- pay.8x8.com
- cloud8.8x8.com
- 8x8.my.site.com (Salesforce community site — check for Salesforce misconfig patterns)
- sipsynergy.co.uk

## Recon TODO
- [ ] Run subfinder/amass against 8x8.com, fuze.me, callroute.com, callroute.io — diff against this list for anything new
- [ ] httpx the full list — note live hosts, status codes, tech stack (Wappalyzer/httpx -tech-detect)
- [ ] Screenshot each live host (aquatone/gowitness) — flag anything that looks like an internal tool, admin panel, or default install page
- [ ] Check each for: directory listing, exposed .git/.svn, phpinfo.php, actuator/swagger endpoints, default creds pages
- [ ] Note tech stack per host in a table here once identified
