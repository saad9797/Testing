# SCOPE_MATRIX.md

Re-verification of [TARGET_SELECTION.md](TARGET_SELECTION.md) against the live GitLab (HackerOne) policy, re-checked this session. No policy changes were found since TARGET_SELECTION.md was written; this document restates it in matrix form per the requested tracking structure and adds the one clarification this session required.

| Asset | In scope? | Bounty eligible? | Notes |
|---|---|---|---|
| A self-managed GitLab instance I install and own (GDK / Docker / Omnibus) | Yes | Yes (Critical/High per severity table) | The only asset this engagement tests, or would test if a live instance existed here. **No such instance currently runs in this environment** (no Ruby, no Docker) — all work to date is static source analysis against the public `gitlab-org/gitlab` repository. |
| `gitlab.com` (production SaaS) | Explicitly narrowed out by this engagement's own decision | N/A | Technically the primary HackerOne asset and bounty-eligible per policy, but **not tested** in this engagement — my working rule (set in TARGET_SELECTION.md) is to touch only my own instance. This is stricter than the program strictly requires, chosen deliberately to avoid any risk of touching real tenant data. |
| `*.gitlab.cn` / JiHu distribution | Out of scope | Ineligible | Separate legal entity; report to security@gitlab.cn instead. |
| `customer.gitlab.com`, `*.gitlab-private.org`, dangling/sandbox domains, third-party-hosted GitLab subdomains | Out of scope | Ineligible | Per the scope table read in TARGET_SELECTION.md. |
| Source-code repositories (`gitlab-org/gitlab`, `gitaly`, `gitlab-shell`, `gitlab-pages`, `gitlab-runner`) | In scope for research (public) | N/A — reading source isn't itself a submittable finding | The actual basis for every document in this chain. |

**Required request headers:** none apply — no live requests have been made to any GitLab-operated asset in this engagement.

**Rate limits:** none consumed — no live requests made.

**Prohibited testing techniques (from policy, restated):** automated scanning, mass account/project/group creation, spam/high-volume activity, DoS (including volumetric), typosquatting, bypassing HackerOne triage.

**Prohibited/excluded vulnerability classes (restated from TARGET_SELECTION.md):** DoS except unauthenticated-persistent-total-disruption; enumeration/metadata-disclosure without a demonstrated privacy breach; CSRF without impact; standalone prompt injection; the specific listed known Duo/prompt-injection issues; self-managed Runner issues; masked CI/CD variable disclosure via documented behavior; open redirects without a chained impact.

**Duplicate policy:** first-to-report only, no partial credit for later reports of the same root cause.

**Automated scanning:** explicitly disallowed by policy.

**Test accounts:** not applicable to this engagement — no live instance exists to create accounts on. If a GDK/Docker instance is stood up later, self-created accounts on that instance would be the only ones used, per policy ("your own installation").

**Credential requirements:** none obtained or needed for source-level research.

**Excluded endpoints/environments:** GDK-only-reproducible bugs are explicitly excluded from the bounty ("Vulnerabilities that are only reproducible in our GitLab Development kit") — any candidate found via source reading must be confirmed against a normal release build before it would be submittable, not just a GDK checkout.

**Conclusion for this session:** every live test in this engagement, if and when one occurs, must map to "my own instance" specifically — never to `gitlab.com` or any other party's data. Nothing in this session performed a live test against anything.
