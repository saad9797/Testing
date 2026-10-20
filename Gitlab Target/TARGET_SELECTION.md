# TARGET_SELECTION.md

Date of research: 2026-09-24. No testing has been performed against anything.

## Selected target

**Program:** GitLab Bug Bounty Program (HackerOne, managed by HackerOne, Gold Standard Safe Harbor)
https://hackerone.com/gitlab

**Exact in-scope asset:** `Your Own GitLab Instance` (HackerOne scope entry; tech: PostgreSQL, Rails, Ruby; type "Other"; coverage *In scope*, max severity *Critical*, bounty *Eligible*), tied to the source-code asset
`https://gitlab.com/gitlab-org/gitlab` (Ruby/Rails/JS/Vue/PostgreSQL; *In scope*, *Critical*, *Eligible*).

Other in-scope source-code assets (same table): gitlab-org/gitaly, gitlab-shell, gitlab-pages, gitlab-runner, gitlab-vscode-extension.

**Plan is to test ONLY a self-hosted instance (GDK or standalone install) that I own. gitlab.com is NOT to be touched** unless separately approved, and even then only per the rules below.

## Exact authorization evidence

Quoted from the program policy page (retrieved 2026-09-24, policy "Last updated on July 21, 2026"; scope "Last updated May 27, 2026"):

- "Disruptive activity such as that listed above can be researched freely on your own installation of gitlab. GitLab is an open-core company, with the source code powering GitLab.com available in the main GitLab Project. You are encouraged to install your own standalone instance for researching vulnerabilities."
- "We strongly encourage security testing on your local GitLab Development Kit (GDK) instance rather than GitLab.com for most vulnerability research."
- "All GitLab Inc. products are in scope unless explicitly noted otherwise."
- Scope table lists **"Your Own GitLab Instance"** as In scope / Critical / Bounty Eligible.
- "The Gold Standard Safe Harbor applies. Practices authorized under this GitLab HackerOne Bug Bounty Program policy are exceptions to GitLab's Acceptable Use Policy."
- Supporting blog: https://about.gitlab.com/blog/gitlab-bug-bounty-program-policy-updates/ (Jan 2026 policy update, GDK emphasis).

### Caveat that must be respected (ambiguity check)
The out-of-scope list contains: **"Vulnerabilities that are only reproducible in our GitLab Development kit."** So the GDK is the recommended sandbox, but a finding must reproduce on a normal release build (CE/EE package or Docker install of a supported version). Plan: use an Omnibus/Docker install of the latest supported release as the confirmation target, GDK/source checkout for code reading and debugging.

## Prohibited activities (from policy)

- Testing against projects, groups, accounts or instances you do not own; accessing other users' private data.
- Anything disruptive on GitLab.com: spam, mass creation of users/groups/projects, abuse requests, typosquatting/namesquatting, high-volume activity, submitting requests to third-party systems.
- **Never test DoS on GitLab.com.** Volumetric attacks are never eligible.
- Unverified automated-tool reports (immediate disqualification); automated scanning reports out of scope.
- Requesting Developer access to GitLab projects / Community Forks group.
- Creating additional credentials from leaked credentials; publishing PoC videos publicly before disclosure.
- Bypassing HackerOne triage (contacting GitLab staff/opening GitLab issues directly).
- Third-party-software sites, customers' GitLab installs, JiHu/gitlab.cn, `*.runway.gitlab.net`, gitlabsandbox.net, etc. are out of scope.

## Permitted activities

- Full-depth testing (including disruptive tests, DoS demonstration on a properly sized self-managed instance) on my own installation.
- Reading and analysing all public source code.
- On gitlab.com only when a bug needs production architecture: use test accounts with a `handle@wearehackerone.com` email/alias, log IPs, follow rules of engagement (not planned).
- Third-party dependency bugs, if: new/unpatched or patch >30 days old, working PoC, Critical/High impact to GitLab.

## Out-of-scope vulnerability classes (avoid wasting time)

DoS (except unauthenticated *persistent total* service disruption), rate limiting, user/project enumeration and yes/no guess-validation oracles, private-object counts/ID disclosure, missing headers/cookie flags, open redirects (unless chained), CSRF with no impact, masked CI/CD variable disclosure, self-managed Runner issues, banned-user behaviours, attacks requiring a victim to leak a privileged token, MITM, most HTML injection, standalone prompt injection (listed known Duo cases excluded), static-analysis-only AI reports.

## Submission requirements

- Every report needs a reproduction artifact (screen capture, video or logs) against my own GitLab install; otherwise closed N/A.
- Severity scoring: any bug needing an account is scored "Privileges Required: Low" (not None).
- Use the public CVSS bounty calculator.

## Bounty range

| Severity | Range |
|---|---|
| Low | $100 – $750 |
| Medium | $1,000 – $2,500 |
| High | $5,000 – $15,000 |
| Critical | $20,000 – $35,000 |

Program stats: $7.4M total paid, ~$504k in last 90 days, 4,212 reports/90 days, 2,257 resolved, avg time to bounty ~1 month. Ultimate self-hosted licence offered after 3 valid findings. Doc-only security fixes get $100.
Note: the reward table header says "Last updated November 22, 2021"; the policy body is more recent. Confirm current amounts at submission time.

## Relevant technology

Ruby on Rails monolith (app/, lib/, ee/), Grape REST API, GraphQL (graphql-ruby, subscriptions), Sidekiq, PostgreSQL, Redis, Workhorse (Go reverse proxy), Gitaly (Go, gRPC git backend), GitLab Shell (Go), Pages (Go), Runner (Go), Vue frontend, Markdown/banzai pipeline, Elasticsearch/Zoekt (Advanced Search), Duo/AI gateway (Python; prompt injection mostly excluded).

## Public repositories

- https://gitlab.com/gitlab-org/gitlab (main, CE + `ee/`)
- https://gitlab.com/gitlab-org/gitaly
- https://gitlab.com/gitlab-org/gitlab-shell
- https://gitlab.com/gitlab-org/gitlab-pages
- https://gitlab.com/gitlab-org/gitlab-runner
- https://gitlab.com/gitlab-org/gitlab-development-kit (GDK)
- Read-only mirrors exist on GitHub (gitlabhq/gitlabhq for CE).
- Security fixes are published to the public repos at patch release; public issues for resolved reports 90 days after fix.

## Historical CVEs / advisories (verified from GitLab's own patch-release page unless noted)

Latest critical patch release, **2026-09-10** (19.3.2 / 19.2.6 / 19.1.8), https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/ :

| CVE | Class | CVSS |
|---|---|---|
| CVE-2026-85706 | Path traversal in repository commits API (unauth arbitrary file read) | 10.0 |
| CVE-2026-87719 | Insecure deserialization, GraphQL subscription serializer | 9.9 |
| CVE-2026-88765 | Buffer overflow, Unicode conversion wrapper (Advanced Search indexing) | 8.5 |
| CVE-2026-79708 | Scheduled Pipeline Execution Policy privilege escalation | 8.5 |
| CVE-2026-78252 | XSS in Markdown JSON table renderer | 8.2 |
| CVE-2026-13210 | Incorrect authorization in CI/CD env var scope | 7.7 |
| CVE-2026-86340/86341 | Protected environment approval bypass | 4.4 |
| CVE-2026-12910 | SAML SSO enforcement bypass | 5.4 |
| CVE-2026-82837 | Workhorse senddata credential exposure | 5.3 |

- 2026-09-11: CVE-2026-85706 added to CISA KEV (exploited in the wild), reported by Rapid7 / SOC Prime (secondary sources, not independently verified by me).
- 2026-09-23: fixes for CVE-2026-85706 and CVE-2026-87719 backported to 19.0.9 and 18.11.12 (search-reported; confirm on docs.gitlab.com/releases/patches/).
- Full history: https://about.gitlab.com/releases/categories/releases/ and https://advisories.gitlab.com/ ; a security patch release ships roughly every two weeks, giving a constant supply of patched commits to diff.
- Also see the GitLab Duo/GraphQL-related items above; DoS-in-GraphQL CVEs exist but DoS is largely out of scope for the bounty.

## Likely attack surfaces

1. **Authorization boundaries**: REST (Grape) and GraphQL resolvers/policies (DeclarativePolicy), project/group/visibility checks, confidential issues, protected environments/branches, token scopes.
2. **Path/file handling**: repository API endpoints (commits, files, archives), Workhorse `senddata`/`sendfile`, uploads, import/export (project import tarballs, bulk import), Gitaly RPC parameters.
3. **Deserialization / GraphQL subscriptions / Sidekiq args**: recent critical class.
4. **Markdown/banzai and frontend rendering**: stored XSS, sanitisation bypasses, Content Editor, Mermaid/KaTeX/table renderers.
5. **CI/CD**: pipeline execution policies, variable scoping, job token permissions, cross-project artifact access.
6. **Authentication**: SAML/OAuth/OmniAuth, 2FA enforcement, session/token handling, SCIM.
7. **Integrations & SSRF**: webhooks, import-by-URL, Jira/Slack/other integrations, Kubernetes agent, DNS rebinding/URL-blocker bypasses.
8. **Go components**: Gitaly/gitlab-shell/Pages/Workhorse argument injection, memory safety in cgo/unicode handling, Pages domain/serving logic.
9. **Package registries** (generic, Maven, npm, etc.) and Terraform state API authorization.

## Why this is suitable for source-assisted research

- Explicit, written permission to attack a self-hosted instance with no restrictions, plus "In scope / Critical / Bounty Eligible" row in the scope table and Gold Standard Safe Harbor. No need to touch production.
- Entire application source is public, including the `ee/` directory, and it can be run locally via GDK or Docker.
- Very rich history: hundreds of resolved reports (303 against "Your Own GitLab Instance"), public disclosures after 90 days, biweekly patch releases with public diffs, so variant analysis and patch diffing are directly productive.
- Large, complex trust model (visibility levels, groups/projects inheritance, tokens, CI, integrations) with real security boundaries, several recent Critical/High classes.
- Top payouts among open-source programs ($20k–$35k critical), still actively paying (~$504k in the last 90 days) as of this research.
- Runs on a well-known stack (Rails/Go), so static and dynamic analysis tooling applies.

## Risks / things to know

- High competition (4,212 reports in 90 days, 1,000+ thanked hackers); duplicates are decided by fix, so novelty matters, and patch-diffing recent CVEs may be a duplicate of already-fixed issues. Target unreleased/newer features or under-reviewed components.
- Strict evidence rule: reports without a video/logs from my own instance are closed N/A; AI-assisted/static-only reports without proven exploitability are rejected.
- Must reproduce on a released build, not only a GDK.
- Many low-value classes excluded (see list above).

## Candidates rejected

- **Nextcloud (HackerOne)**: ended bounty payouts on April 22, 2026 (AI-slop volume); no rewards.
- **curl**: ended its bug bounty in January 2026.
- Not verified/considered further: others whose current authorization/reward status I could not confirm from primary sources.

## Sources

- https://hackerone.com/gitlab (policy and scope tabs, read 2026-09-24)
- https://about.gitlab.com/blog/gitlab-bug-bounty-program-policy-updates/
- https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/
- https://nextcloud.com/blog/updates-about-the-nextcloud-bug-bounty-program/
- https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/
