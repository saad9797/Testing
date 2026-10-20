# Slice A — Intellectual Property on Public Domains (leaked secrets / OSINT)

Status: ACTIVE. Eligible asset (Low $50 / Med $100 / High $250 / Crit $500).
Attacker model: A1 (remote unauthenticated). Touches only public third-party
sources (GitHub, npm, paste sites, CT logs) — NOT 8x8 infra, so no X-HackerOne
header needed and no "high-volume testing" risk for the search step itself.

## Why this slice (Phase 1 evidence)
This exact class has been accepted & paid multiple times:
- #1957430 — credentials leaked on GitHub (by top hacker "pentestor")
- #1368690 — hardcoded AWS credentials in a downloadable .msi (High)
- #504122  — config files exposed by a site running an 8x8 web app
The eligible "Intellectual Property on Public Domains" asset has 29 resolved reports.

## Invariant being tested
"No 8x8 secret, credential, internal token, or proprietary source should be
retrievable from a public domain." Violated whenever a valid, currently-working
8x8 secret appears in a public repo/package/paste.

## ‼️ Validation rule before reporting
A leak only counts if the secret is (a) genuinely 8x8's and (b) *still valid*.
Do NOT actively use a found credential against 8x8 production to "prove" it —
that can breach scope/CFAA-style limits and the safe harbor is for good-faith
testing. Prove validity the least-invasive way (e.g. an AWS key: `aws sts
get-caller-identity` only if clearly 8x8-owned and you have H1 auth context, or
just report it as an unverified-but-live-looking leak and let triage confirm).
When in doubt, report without exploiting. Credential stuffing is explicitly banned.

---

## GitHub dorks — run at https://github.com/search (Code tab, logged in)

Priority 1 — direct secret patterns tied to in-scope hosts:
```
"vcc-na" 8x8 password
"cpaas-net.8x8.com"
"chalet.8x8.com"
"sms.8x8.com" (apikey OR api_key OR token OR secret)
"jaas.8x8.vc" (secret OR jwt OR apikey)
"8x8.vc" appId secret
"wavecell" (apikey OR api_key OR "api key" OR password)
"8x8cloud.net"
"packet8.net" password
```

Priority 2 — file-scoped:
```
"8x8.com" filename:.env
"wavecell" filename:.env
"8x8" filename:config extension:json password
org secrets in Android app: "org.vom8x8.sipua" (apikey OR secret)
```

Priority 3 — key formats near 8x8 refs:
```
"8x8" "AKIA"                 (AWS access key id)
"8x8" "-----BEGIN RSA PRIVATE KEY-----"
"wavecell" "Authorization: Bearer"
```

Tips:
- Pivot on any unique internal string you find (a hostname, a var name like
  `X8_`, an internal package name) — the second dork is always better than the first.
- Check both Code and Commits tabs; secrets often live in deleted-but-committed history.
- Sort by "Recently indexed" to beat other hunters to fresh leaks.

## npm / package registries
- 8x8's public npm org: https://www.npmjs.com/org/8x8 and search `@8x8/`.
  The scope even lists `@8x8/pui-partner-comm`. Inspect published packages for
  committed secrets, internal URLs, or `.npmrc` tokens in the tarball.
- `npm view @8x8/<pkg>` then download the tarball and grep for secrets offline.

## Other public-domain sources
- Postman public workspaces: search "8x8" / "wavecell" for collections with live keys.
- DockerHub: search 8x8/wavecell images; `docker history` / layer inspection for baked-in secrets.
- Paste sites via Google: `site:pastebin.com 8x8.com` , `"vcc-na" 8x8`.
- APKs: 8x8 Work Android (`org.vom8x8.sipua`) — decompile & grep for hardcoded
  keys (this is how #1368690-style findings happen). NOTE: the Android app asset
  is INELIGIBLE in current scope, but secrets found in it that grant access to an
  ELIGIBLE backend (e.g. an sms.8x8.com key) are reportable via the IP asset.

## Log findings here (per hit)
```
### [date] <what leaked>
Source URL:
Secret type / value (redact partially):
Which 8x8 asset it affects & whether that asset is bounty-eligible:
Validity evidence (least-invasive):
Severity estimate:
```
