# ATTACK_SURFACE_SLICES.md — GitLab (self-managed instance)

Scope authority: [TARGET_SELECTION.md](TARGET_SELECTION.md). No testing performed. This document divides the target into 20 thin, independently-auditable slices, maps each one's data flow, and ranks them using the accumulated evidence in [HISTORICAL_VULNERABILITY_MODEL.md](HISTORICAL_VULNERABILITY_MODEL.md), [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md), and [PATCH_ARCHAEOLOGY.md](PATCH_ARCHAEOLOGY.md) — not on which slice is generically considered "high risk" in security folklore. Several slices below are deliberately ranked low despite being popular audit targets elsewhere (SSRF is the clearest example) because the evidence in this specific codebase shows the obvious version of that bug is already hardened.

Each slice is mapped as: **entry points → input → validation → transformation → authorization → sensitive sink**, plus the attacker-chain shape: **attacker → trust boundary → privileged operation → victim/resource**. Evidence citations point back to the specific class/entry/invariant they come from rather than restating full detail.

---

## 1. Authentication

- **Entry points:** session login (Devise/Warden), `PRIVATE-TOKEN` header, OAuth2 Bearer, CI `JOB-TOKEN`, deploy token, LFS basic-auth, feed/static-object token, runner token, DPoP, SAML/OIDC/LDAP callbacks.
- **Input:** credentials, tokens, SAML assertions.
- **Validation:** per-credential-type checks in `Gitlab::Auth::AuthFinders` (10 parallel paths, [SYSTEM_CONTEXT.md §2](SYSTEM_CONTEXT.md)); SAML signature verification (ruby-saml).
- **Transformation:** credential → resolved `User`/`DeployToken`/`Ci::Runner` object; composite-identity resolution for agent/service accounts.
- **Authorization:** scope validation (`Gitlab::Auth::ScopeValidator`), admin-mode step-up.
- **Sensitive sink:** `current_user` bound for the rest of the request lifecycle — every downstream authorization decision inherits from this.
- **Attacker chain:** attacker (network, no creds) → trust boundary: "only a cryptographically valid credential/assertion authenticates" → privileged operation: session established as an arbitrary/victim user → resource: entire account.
- **Evidence:** CVE-2022-1162 (hardcoded OmniAuth password, Critical, [Class 9](HISTORICAL_VULNERABILITY_MODEL.md)); CVE-2024-45409 + 2 follow-on advisories (SAML parser differential, Critical, [Class 8](HISTORICAL_VULNERABILITY_MODEL.md), [Entry 3](PATCH_ARCHAEOLOGY.md)). **3 Critical CVEs**, but SAML-class risk reduces to a version-pin check ([INV-08](SECURITY_INVARIANTS.md)) and the hardcoded-password class is a narrow, non-recurring logic bug ([Class 9](HISTORICAL_VULNERABILITY_MODEL.md) point 11).

## 2. Authorization

- **Entry points:** every REST (`lib/api/*.rb`) and GraphQL (`app/graphql/types/*`, `resolvers/*`) endpoint; DeclarativePolicy (`app/policies/*`).
- **Input:** object IDs/IIDs/GlobalIDs, project/group context.
- **Validation:** `Ability.allowed?(user, :ability, subject)` → `*Policy` classes; Finder-class scoping (`app/finders/*`).
- **Transformation:** ID → loaded ActiveRecord object (via `.find` or a Finder) → policy evaluation.
- **Authorization:** the policy/Finder check itself — this slice's whole purpose.
- **Sensitive sink:** any confidential/private field or write action on the resolved object.
- **Attacker chain:** attacker (any authenticated user, sometimes unauthenticated) → trust boundary: "an ID-keyed lookup re-applies the same visibility/confidentiality rule the default listing view enforces" → privileged operation: read/act on an object outside the attacker's actual permission scope → resource: confidential issues/notes, private group data, another user's pipeline/CI data, or (CI/CD variant) another user's effective *execution identity*.
- **Evidence:** highest CVE density found in this entire research effort — **8 distinct CVEs**: CVE-2022-1352, CVE-2022-1545, CVE-2026-1080, CVE-2025-14594 (IDOR/BOLA, [Class 12](HISTORICAL_VULNERABILITY_MODEL.md)) + CVE-2024-6385, CVE-2024-5655, CVE-2024-9164, CVE-2024-11669 (CI/CD business-logic authorization, [Class 11](HISTORICAL_VULNERABILITY_MODEL.md)). Independently *predicted* from architecture alone before the CVE evidence was gathered ([SYSTEM_CONTEXT.md §3, Flow C](SYSTEM_CONTEXT.md)). Actively recurring through 2026, not a closed historical chapter. The mechanism behind the two highest-severity instances (CVE-2024-6385/-5655) remains **fully undisclosed** — the single biggest open question in the whole research chain ([PATCH_ARCHAEOLOGY.md, closing section](PATCH_ARCHAEOLOGY.md)).

## 3. Session/token handling

- **Entry points:** same as Authentication, plus token-exchange/derivation logic.
- **Input:** an already-authenticated credential of one type.
- **Validation:** scope/type checks meant to prevent a narrow credential from acting as a broader one.
- **Transformation:** job token → (should never become) session token.
- **Authorization:** `route_authentication_setting[:job_token_allowed]` + job-token-scope allowlist ([SECURITY_INVARIANTS.md INV-03](SECURITY_INVARIANTS.md)).
- **Sensitive sink:** any endpoint reachable with the upgraded/wrong-scoped credential.
- **Attacker chain:** attacker (holder of a victim's job token) → trust boundary: "credential types have hard, non-transitive privilege boundaries" → privileged operation: obtaining a session token from a job token → resource: victim's full interactive session.
- **Evidence:** CVE-2024-8641 (job-token→session-token, Medium, [Class 11.2](HISTORICAL_VULNERABILITY_MODEL.md)) + CVE-2024-11669 (job-token scope too broad, [Class 11.3](HISTORICAL_VULNERABILITY_MODEL.md)) — 2 CVEs, overlaps substantially with Slice 2's CI/CD-token evidence rather than being fully independent.

## 4. Multi-tenant isolation

- **Entry points:** any namespace/group/project-scoped query, Sidekiq job argument, search index query.
- **Input:** a project/group/namespace identifier.
- **Validation:** `Project.public_or_visible_to_user`-style scoped queries vs. raw `.find`.
- **Transformation:** namespace hierarchy traversal (parent/descendant group resolution).
- **Authorization:** same DeclarativePolicy layer as Slice 2 — this slice is largely **the same underlying mechanism as Authorization, viewed through the "tenant boundary" lens** rather than an independent one ([HISTORICAL_VULNERABILITY_MODEL.md](HISTORICAL_VULNERABILITY_MODEL.md), closing note: "the closest matches are the IDOR/BOLA class... a tenant/visibility-boundary failure under a different name").
- **Sensitive sink:** cross-tenant data (another namespace's issues, CI variables, search results).
- **Attacker chain:** attacker (any tenant) → trust boundary: namespace/project scoping in one shared DB/fleet, enforced entirely in application code, no container isolation ([SYSTEM_CONTEXT.md §4](SYSTEM_CONTEXT.md)) → privileged operation: read/write another tenant's data → resource: another organization's private repository content.
- **Evidence:** CVE-2026-1080 ("private descendant groups," [Class 12](HISTORICAL_VULNERABILITY_MODEL.md)) is a direct tenant-hierarchy-boundary hit; otherwise this slice's evidence is a subset of Slice 2's — no additional CVEs found beyond what Slice 2 already counts.

## 5. File upload/download

- **Entry points:** Workhorse-accelerated multipart uploads, direct-download/blob/attachment routes, `UploadsRewriter`-style copy-on-move operations.
- **Input:** file bytes + a path/filename-shaped parameter (route segment, markdown-embedded reference, or Workhorse-signed JWT payload).
- **Validation:** two non-unified mechanisms — `File.realpath` + fixed allowlist (`lib/uploaded_file.rb`, upload-ingest only) vs. `Gitlab::PathTraversal` regex blocklist (general, with a documented body-blind, 12-name-exemption Rack middleware layer, [PATCH_ARCHAEOLOGY.md Entry 2](PATCH_ARCHAEOLOGY.md)).
- **Transformation:** path-shaped parameter → disk/object-storage path or Gitaly RPC argument.
- **Authorization:** project/group membership check on the *containing* object — frequently separate from the path-validity check itself.
- **Sensitive sink:** `File.read`/`send_file`/object-storage fetch/copy operation.
- **Attacker chain:** attacker (unauthenticated, in 2 of 3 historical instances) → trust boundary: "a path-shaped parameter can never resolve outside its intended root" → privileged operation: arbitrary local file read → resource: `secrets.yml`, database credentials, source code, other users' uploaded files.
- **Evidence:** **3 major, high-severity incidents**: HackerOne #827052 (2020, arbitrary file read chained to RCE via leaked `secret_key_base` + Marshal cookie forgery), CVE-2023-2825 (2023, CVSS 10.0, unauthenticated), CVE-2026-85706 (2026, CVSS 10.0, unauthenticated, **actively exploited, CISA KEV** — cited in [TARGET_SELECTION.md](TARGET_SELECTION.md)). Same class recurring at Critical severity across 6 years, most recent instance confirmed exploited in the wild as of this research. This is the only slice with a **currently-active KEV entry**.

## 6. URL fetching / SSRF

- **Entry points:** webhook "Test" trigger, project/group import-by-URL, CI Lint API, avatar-by-URL, remote mirrors, dependency proxy.
- **Input:** an attacker-supplied URL/hostname.
- **Validation:** `Gitlab::HTTP_V2::UrlBlocker` (blocklist of loopback/private/link-local ranges + DNS-rebind IP-pinning at request time).
- **Transformation:** hostname → resolved IP → outbound TCP connection.
- **Authorization:** project Maintainer-level access to create/edit the URL-bearing resource (except the unauthenticated CI-Lint variant).
- **Sensitive sink:** the actual outbound HTTP request + response readback.
- **Attacker chain:** attacker (Maintainer, or unauthenticated for the CI-Lint variant) → trust boundary: "the IP validated is the IP connected to" → privileged operation: server-initiated request to internal network/cloud metadata → resource: internal services, cloud credentials.
- **Evidence:** highest **volume** of any class (≥3 independent 2019 reports: HackerOne #513098/#541169/#632101, CVE-2019-5464) + CVE-2021-22214, but [SYSTEM_CONTEXT.md §13](SYSTEM_CONTEXT.md) and [SECURITY_INVARIANTS.md INV-04](SECURITY_INVARIANTS.md) directly confirmed, by reading current source, that the specific 2019 mechanism is now fixed and durable (IP-pinning active in `Gitlab::HTTP` at request time). **Ranked low despite high historical volume specifically because the evidence shows the popular version of this bug is already closed** — the residual risk is narrow (a new code path bypassing the wrapper), not a live architectural gap.

## 7. Webhooks

- Functionally a **subset of Slice 6** (the delivery mechanism for most historical SSRF instances) plus its own authentication direction (GitLab → third party, not third party → GitLab, since GitLab has no inbound-webhook-receiver feature per [SYSTEM_CONTEXT.md §13](SYSTEM_CONTEXT.md)).
- **Entry points:** webhook create/edit/test.
- **Input/validation/transformation/sink:** identical to Slice 6.
- **Authorization:** project Maintainer+ to configure; the outbound request itself carries no inbound authentication concern.
- **Evidence:** same citations as Slice 6 — not counted twice for ranking purposes. Kept as a separate slice per the requested taxonomy, but contributes no independent evidence.

## 8. OAuth/OIDC

- **Entry points:** `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, OmniAuth provider callbacks, Doorkeeper device-authorization grant.
- **Input:** authorization codes, redirect URIs, client credentials, device codes.
- **Validation:** Doorkeeper's registered-redirect-URI allowlist; PKCE; scope checks.
- **Transformation:** authorization grant → access/refresh token.
- **Authorization:** application-level scope grants (`ADMIN_SCOPES`, `optional_scopes`, [SYSTEM_CONTEXT.md §14](SYSTEM_CONTEXT.md)).
- **Sensitive sink:** the issued access token, and any redirect that could carry it off-origin.
- **Attacker chain:** attacker (gets a victim to click a link) → trust boundary: "an OAuth access token issued via implicit/fragment flow only ever reaches the app's own registered redirect URI" → privileged operation: token exfiltration via a chained open redirect → resource: victim's third-party-provider-linked account.
- **Evidence:** **5 recurring instances over 7 years** — HackerOne #221432 (2017), CVE-2022-2250, GitLab's own admitted-incomplete fix ([issue #377810](https://gitlab.com/gitlab-org/gitlab/-/issues/377810)), CVE-2024-4283, CVE-2024-4612 ([Class 3](HISTORICAL_VULNERABILITY_MODEL.md), full diff-level archaeology in [PATCH_ARCHAEOLOGY.md Entry 1](PATCH_ARCHAEOLOGY.md)). The longest-spanning recurring pattern found in this entire research effort, with a **direct, written GitLab admission** that a fix was incomplete — and the sibling routes named in that admission were not confirmed fixed in this research.

## 9. Password/account recovery

- **Entry points:** `passwords_controller.rb` (Devise `recoverable`), 2FA/WebAuthn recovery.
- **Input:** email/username parameter(s).
- **Validation:** ownership verification (intended) before token delivery.
- **Transformation:** reset request → emailed token → password change.
- **Authorization:** none needed by design (self-service); the invariant is *destination* verification, not permission.
- **Sensitive sink:** the password-reset link's delivery address.
- **Attacker chain:** attacker (unauthenticated) → trust boundary: "a reset token is only ever delivered to a previously-verified address" → privileged operation: attacker receives the victim's reset link → resource: full account takeover.
- **Evidence:** CVE-2023-7028 (Critical, CVSS 10.0, zero-click, parameter pollution, [Class 10](HISTORICAL_VULNERABILITY_MODEL.md)) — 1 CVE, but maximal severity; narrow, non-recurring logic bug rather than an architectural pattern with confirmed siblings ([SECURITY_INVARIANTS.md INV-10](SECURITY_INVARIANTS.md)).

## 10. Deserialization

- **Entry points:** project/group import-export, GraphQL subscription payloads.
- **Input:** an attacker-authored export tarball or subscription argument.
- **Validation:** `YAML.safe_load_file` + `permitted_classes` allowlist + `attributes_permitter.rb` (import-export, confirmed hardened by direct source read, [SYSTEM_CONTEXT.md §10/11](SYSTEM_CONTEXT.md)).
- **Transformation:** serialized structure → ActiveRecord objects.
- **Authorization:** import-permission check on the target namespace.
- **Sensitive sink:** object instantiation/attribute assignment; GraphQL subscription-serializer object construction.
- **Attacker chain:** attacker (import permission) → trust boundary: "a deserialized structure can only produce allowlisted classes/attributes" → privileged operation: arbitrary object construction/attribute injection → resource: server-side state or code execution.
- **Evidence:** the obvious top-level bug (unsafe YAML/Marshal load in import-export) is **confirmed already mitigated** by direct source read; the only fully-identified GitLab-specific deserialization CVE is CVE-2026-87719 (GraphQL subscription serializer, Critical, [TARGET_SELECTION.md](TARGET_SELECTION.md)/[Class 15](HISTORICAL_VULNERABILITY_MODEL.md)), whose fix mechanics were not located ([THREAT_MODEL.md T2-B](THREAT_MODEL.md)). 1 confirmed CVE + 1 confirmed-mitigated historical near-miss.

## 11. Template rendering

- **Entry points:** Markdown/Banzai pipeline (issues, MRs, wikis, commit messages).
- **Input:** user-authored Markdown/rich-text content.
- **Validation:** `nokogiri`-based sanitization filters in the Banzai pipeline.
- **Transformation:** Markdown → HTML.
- **Authorization:** none (content-authoring permission only).
- **Sensitive sink:** rendered HTML in another user's browser (stored XSS).
- **Attacker chain:** attacker (any content-authoring user) → trust boundary: "the sanitization filter runs on every path that renders user content, and no filter/extension can reintroduce raw HTML after it" → privileged operation: stored XSS → resource: victim's authenticated session (session-riding, not token theft, since GitLab is cookie-session-based for browser use).
- **Evidence:** CVE-2026-78252 ("XSS in Markdown JSON table renderer," High, [TARGET_SELECTION.md](TARGET_SELECTION.md) patch table) — 1 CVE identified, no deeper archaeology performed on it in this research chain; thin evidence relative to other slices.

## 12. Parser boundaries (native/C-extension dependencies)

- **Entry points:** any feature that hands attacker-reachable bytes to a native-extension parser: `.ipynb` diff rendering (Oj), SAML assertion parsing (REXML/Nokogiri), image metadata extraction (historically ExifTool), Advanced Search indexing (Unicode conversion).
- **Input:** raw bytes of a file/document the attacker controls (repository content, an uploaded image, a SAML response).
- **Validation:** intended to be strict type/size/depth checking inside the native code — historically absent or inconsistent between sibling functions.
- **Transformation:** bytes → native in-memory structure (parse tree, doc buffer).
- **Authorization:** none — the whole point of these bugs is that ordinary content-authoring/upload permission is sufficient.
- **Sensitive sink:** native memory operations (buffer writes, pointer dereferences) or an `eval`-equivalent embedded in the parser.
- **Attacker chain:** attacker (ordinary push/upload access, or unauthenticated for the 2021 case) → trust boundary: "a native parser bounds-checks every size/depth field derived from untrusted input" → privileged operation: memory corruption or code evaluation inside the parser → resource: full OS-level code execution as the app's worker user.
- **Evidence:** **highest peak severity** of any slice — CVE-2021-22205 (unauthenticated RCE, KEV, [Class 6](HISTORICAL_VULNERABILITY_MODEL.md)), CVE-2026-54902 chain + siblings (authenticated full RCE via Oj, [Class 7](HISTORICAL_VULNERABILITY_MODEL.md), [PATCH_ARCHAEOLOGY.md Entry 5](PATCH_ARCHAEOLOGY.md) — including a directly-confirmed "sibling function missing the same bounds check" pattern), CVE-2024-45409+2 (SAML parser differential, also arguably belongs to Slice 1), CVE-2026-88765 (Unicode conversion buffer overflow, [TARGET_SELECTION.md](TARGET_SELECTION.md)). **4 distinct dependency/mechanism families**, multiple Critical/KEV. However, the actionable remediation for nearly all of these is a **version-pin comparison**, not open-ended source auditing ([THREAT_MODEL.md T2-C](THREAT_MODEL.md)) — high severity, low "slice depth" for further audit.

## 13. API request parsing

- **Entry points:** `/api/graphql` (single + multiplex/batched), REST Grape endpoints, Workhorse-forwarded multipart bodies.
- **Input:** GraphQL query text/variables, REST JSON bodies, multipart fields.
- **Validation:** depth/complexity limits, CSRF applicability logic (`any_mutating_query?`), body-size limits per Workhorse route.
- **Transformation:** raw request → parsed query/AST → executed operation.
- **Authorization:** `authorize_access_api!`, per-field GraphQL `authorize` declarations.
- **Sensitive sink:** mutation execution, especially where CSRF/GET-safety assumptions are load-bearing.
- **Attacker chain:** attacker (gets an authenticated victim to load a page, or crafts a batched request) → trust boundary: "the operation validated is the operation executed" → privileged operation: a mutation executes under GET or without CSRF token → resource: any state-changing GraphQL operation.
- **Evidence:** CVE-2026-19478 (GraphQL code injection via implicit field-resolver dispatch, CVSS 9.4) + CVE-2026-19650 (CSRF via multiplex batching, shared-mutable-tracer-state divergence) — both fully diffed at the source level in [PATCH_ARCHAEOLOGY.md Entry 4](PATCH_ARCHAEOLOGY.md), confirmed fixed in current source by direct read; plus the 2020 Workhorse request-smuggling trio (CVE-2020-6833/-11505/-11506, [Class 13](HISTORICAL_VULNERABILITY_MODEL.md)). **5 CVEs**, 2 of them among the most recently and most thoroughly source-verified findings in this whole research chain, but both already fixed as of the current checkout.

## 14. Background jobs (Sidekiq)

- **Entry points:** any `ApplicationWorker` subclass (484 classes, [SYSTEM_CONTEXT.md §10](SYSTEM_CONTEXT.md)).
- **Input:** job arguments serialized to Redis (typically IDs).
- **Validation:** none inherent to the queue itself — each worker must re-validate at `#perform` time.
- **Transformation:** ID argument → re-loaded object at execution time (possibly stale relative to enqueue time).
- **Authorization:** inconsistent — some workers re-check, some assume the enqueue-time check still holds ([SYSTEM_CONTEXT.md §4](SYSTEM_CONTEXT.md), [SECURITY_INVARIANTS.md INV-03](SECURITY_INVARIANTS.md)).
- **Sensitive sink:** whatever privileged action the worker performs.
- **Attacker chain:** attacker (can influence what gets enqueued, e.g. via a pipeline trigger) → trust boundary: "the authorization decision made at enqueue time still holds at execution time" → privileged operation: a stale/incorrect authorization context is used → resource: cross-tenant or cross-user action.
- **Evidence:** **no disclosed CVE directly named a specific Sidekiq worker** in any source reviewed; this slice's risk is entirely an **architectural inference** connected to CVE-2024-11222 (pipeline-creation TOCTOU, [Class 14.2](HISTORICAL_VULNERABILITY_MODEL.md)), which is itself a web-request-level race rather than a confirmed Sidekiq-specific instance. Real risk, weak direct evidence.

## 15. Message consumers (incoming email, Mailgun webhook receiver)

- **Entry points:** `app/controllers/mailgun/webhooks_controller.rb` (found in this research's CSRF-exemption scan, [SECURITY_INVARIANTS.md INV-05](SECURITY_INVARIANTS.md)), incoming-email/mailroom processing (`lib/api/internal/mail_room.rb`, [SYSTEM_CONTEXT.md §1](SYSTEM_CONTEXT.md)).
- **Input:** inbound email content, Mailgun webhook payloads.
- **Validation:** Mailgun signature verification (assumed, not confirmed by direct read); reply-by-email parsing.
- **Transformation:** email body → issue/MR comment or action.
- **Authorization:** sender-address-to-user mapping.
- **Sensitive sink:** content injected into an issue/MR as if authored by the mapped user.
- **Attacker chain:** attacker (can send/spoof email or forge a Mailgun webhook call) → trust boundary: "the webhook/email sender is authenticated before its content is trusted as coming from a specific user" → privileged operation: content injection or spoofed authorship → resource: any project the mapped user can post to.
- **Evidence:** **no disclosed CVE found in any source reviewed** for this specific slice; identified only structurally (it appeared in a CSRF-exemption grep, meaning it's an unauthenticated-by-CSRF-standards entry point that must rely entirely on its own signature check). Thinnest evidence base of any slice with at least one concrete entry point identified.

## 16. Plugin/extension boundaries

- **Entry points:** CI/CD Components, Pipeline Execution Policies, Duo/Agent Platform tool definitions, MCP tool endpoints (`app/services/mcp/tools/*`).
- **Input:** component/policy definitions, agent tool-call arguments.
- **Validation:** varies; MCP file-read tools use `Gitlab::PathTraversal` ([SECURITY_INVARIANTS.md INV-02 candidate locations](SECURITY_INVARIANTS.md)).
- **Transformation:** tool-call arguments → underlying API/service invocation.
- **Authorization:** should mirror the equivalent human-facing permission; newest, least battle-tested code in the whole application.
- **Sensitive sink:** whatever the underlying tool grants access to (repository files, CI variables).
- **Attacker chain:** attacker (can influence agent tool-call arguments) → trust boundary: "an agent-invoked tool call carries exactly the invoking human's permissions, no more" → privileged operation: tool call escapes its intended scope → resource: repository/CI data.
- **Evidence:** CVE-2026-79708 ("Scheduled Pipeline Execution Policy test privilege escalation," [TARGET_SELECTION.md](TARGET_SELECTION.md) patch table) is the one concrete CVE touching this general area; the Agent Platform/MCP-specific risk is otherwise **entirely speculative, by construction** ([THREAT_MODEL.md T3-D](THREAT_MODEL.md)) — no historical CVE anchors it, and prompt-injection findings here are explicitly excluded by the bounty program policy.

## 17. Administrative APIs

- **Entry points:** `app/controllers/admin/*`, admin-scoped REST/GraphQL endpoints.
- **Input:** admin-only parameters (user management, instance settings).
- **Validation:** `authenticated_as_admin!` → `Gitlab::Auth::CurrentUserMode#admin_mode?` (step-up, 6-hour window, [SYSTEM_CONTEXT.md §2/§9](SYSTEM_CONTEXT.md)).
- **Transformation:** none beyond normal parameter handling.
- **Authorization:** the specific risk is code checking `current_user.admin?` directly instead of the step-up-aware `admin_mode?` helper.
- **Sensitive sink:** instance-wide configuration, other users' accounts.
- **Attacker chain:** attacker (an authenticated admin-flagged user who has *not* entered admin mode this session, or an attacker who compromised such a session) → trust boundary: "admin-privileged actions require the step-up admin-mode flag, not just the admin bit on the user record" → privileged operation: instance-wide admin action without re-authentication → resource: entire instance.
- **Evidence:** **no disclosed CVE found in any source reviewed** for this specific admin-mode-bypass mechanism; the risk is a plausible, well-reasoned architectural inference from reading `lib/gitlab/auth/current_user_mode.rb` directly ([SYSTEM_CONTEXT.md §2](SYSTEM_CONTEXT.md)), not a confirmed historical pattern.

## 18. Business-logic workflows

- Substantially **the same evidence as Slice 2** (CI/CD pipeline-identity CVEs are business-logic authorization failures) — kept separate per the requested taxonomy but not counted as independent evidence for ranking. The one addition specific to this framing is the approval-count/pipeline-gating race conditions, which are covered more precisely under Slice 19.
- **Evidence:** no independent CVEs beyond Slices 2/19.

## 19. Race conditions

- **Entry points:** MR-approval submission, pipeline-creation-on-commit.
- **Input:** timing of concurrent requests.
- **Validation:** approval-count check, pipeline-authorization check.
- **Transformation:** none — the bug is the *absence* of atomicity between check and act.
- **Authorization:** the check itself is correct in isolation; the failure is TOCTOU, not a missing check.
- **Sensitive sink:** merge action (approval bypass) or pipeline execution (identity confusion).
- **Attacker chain:** attacker (Developer-level, or colluding approvers) → trust boundary: "the state a gating decision was made about is the same state acted upon" → privileged operation: approval-count bypass or acting in another user's commit context → resource: merge-protection integrity, or another user's pipeline-execution identity.
- **Evidence:** CVE-2019-11546 (MR-approval race) + CVE-2024-11222 (pipeline-creation TOCTOU, [Class 14](HISTORICAL_VULNERABILITY_MODEL.md)) — 2 CVEs, five years apart, same shape, both Low-Medium severity historically.

## 20. External integrations

- **Entry points:** `app/models/integrations/*` (Slack, Jira, PagerDuty, generic webhook-based integrations).
- **Input:** integration-specific configuration + inbound/outbound payloads.
- **Validation:** varies per integration; each is architecturally "a mini-plugin with its own trust boundary" ([SYSTEM_CONTEXT.md §5](SYSTEM_CONTEXT.md)).
- **Transformation:** third-party payload → GitLab action (issue creation, notification) or vice versa.
- **Authorization:** integration-configuration permission (Maintainer+).
- **Sensitive sink:** whichever side of the integration is less trusted at a given moment.
- **Attacker chain:** attacker (controls the third-party side, or can configure the integration) → trust boundary: varies per integration → privileged operation: varies → resource: varies.
- **Evidence:** the Jira DVCS open-redirect chain (Slice 8/[Class 3](HISTORICAL_VULNERABILITY_MODEL.md)) is the only concrete CVE-level hit inside a *named* integration; otherwise this slice's evidence largely overlaps with Slices 6/7/8 rather than contributing independently. Jira Connect and Mailgun controllers both appeared in the CSRF-exemption scan ([SECURITY_INVARIANTS.md INV-05](SECURITY_INVARIANTS.md)) as structurally-untested candidates.

---

## Ranking (evidence-weighted, highest first)

| Rank | Slice | Distinct CVEs/reports | Peak severity | Current architectural status |
|---|---|---|---|---|
| 1 | **5. File upload/download** | 3 (2020, 2023, 2026) | Critical, CVSS 10.0 ×2, **active KEV** | Two non-unified defense mechanisms; most recent instance still exploited in the wild |
| 2 | **2. Authorization** | 8 | Critical (CVSS 9.6–9.9 range) | Actively recurring through 2026; highest-severity mechanism (CVE-2024-6385/-5655) fully undisclosed |
| 3 | **8. OAuth/OIDC** | 5 (2017–2024) | High–Critical | GitLab's own written admission of an incomplete fix; sibling routes unconfirmed |
| 4 | 12. Parser boundaries | 4 families | Critical, KEV (2021) | High severity but resolves mostly to version-pin checks |
| 5 | 13. API request parsing | 5 | High–Critical | 2 most-recent instances already fixed and source-confirmed |
| 6 | 1. Authentication | 3 | Critical | Overlaps Slices 8/12; SAML risk is a version check |
| 7 | 6/7. URL fetching / Webhooks | ≥5 (2019–2021) | Critical (historical) | **Confirmed hardened** by direct source read — high volume, low residual risk |
| 8 | 9. Password/account recovery | 1 | Critical | Narrow, non-recurring |
| 9 | 19. Race conditions | 2 | Low–Medium | Confirmed recurring shape, low severity ceiling |
| 10 | 3. Session/token handling | 2 | Medium | Overlaps Slice 2 |
| 11 | 10. Deserialization | 1 confirmed + 1 mitigated | Critical | Obvious path already hardened |
| 12 | 4. Multi-tenant isolation | 1 independent | Critical | Mostly a re-framing of Slice 2 |
| 13 | 11. Template rendering | 1 | High | Thin evidence, no archaeology done |
| 14 | 20. External integrations | overlaps only | — | No independent evidence |
| 15 | 18. Business-logic workflows | overlaps only | — | No independent evidence |
| 16 | 14. Background jobs | 0 direct | — | Architectural inference only |
| 17 | 16. Plugin/extension boundaries | 1 loosely related | — | Mostly speculative; prompt-injection excluded by policy |
| 18 | 17. Administrative APIs | 0 | — | Architectural inference only |
| 19 | 15. Message consumers | 0 | — | Structural candidate only, no CVE |

---

## Top 3 slices selected for further work

### 1. File upload/download
Selected because it has the **only currently-active, in-the-wild-exploited (KEV) vulnerability** tied to any slice in this research, the **same class recurring three times across six years** with matching Critical/CVSS-10.0 severity, and — uniquely among the top slices — a **fully read, current-source-confirmed architectural gap**: [PATCH_ARCHAEOLOGY.md Entry 2](PATCH_ARCHAEOLOGY.md) shows the present-day Rack-level defense explicitly never inspects request bodies and permanently exempts 12 named parameters (`content`, `description`, `body`, `note`, among others) from any check at all. This is not an inference — it is read directly from the deployed code. Concrete next questions (already enumerated) are fast to answer against a live instance: whether the historical `UploadsRewriter` sink was ever fixed at the source, and whether any current feature builds a path from one of the 12 exempted parameter names.

### 2. Authorization
Selected because it has the **highest raw CVE count of any slice (8)**, spans both the "narrow IDOR" flavor (still producing new CVEs as recently as this year) and the "CI/CD business-logic" flavor (5 CVEs in 2024 alone, the single densest CVE cluster found anywhere in this research), and was **independently predicted by architecture review** before the CVE evidence was gathered — two unrelated research methods converging on the same conclusion is the strongest form of evidence available here. It is also the slice with the **largest unresolved question**: the exact mechanism of CVE-2024-6385/CVE-2024-5655 (pipeline-execution-as-arbitrary-user) was never publicly disclosed by GitLab and could not be reconstructed from any source reviewed across this entire research chain — meaning genuinely new research (not just re-verification of a known fix) is required here, unlike most other high-evidence slices.

### 3. OAuth/OIDC
Selected over the higher-peak-severity Parser-boundaries slice specifically because of the evidence's *shape*, not its magnitude: this is the only slice where **GitLab's own engineering team is on the public record stating their own fix was incomplete** ([issue #377810](https://gitlab.com/gitlab-org/gitlab/-/issues/377810)), the pattern has recurred **five times across seven years** (the longest span of any slice), and the specific sibling routes named in that admission (`config/routes/project.rb`'s `commit/:id`/`tree/*id`, `config/routes/repository_deprecated.rb`'s `logs_tree/*path`) were identified but **never confirmed fixed** in this research — a concrete, named, unresolved lead rather than a general architectural worry. Parser boundaries (rank 4) was deliberately not selected for the top 3 despite higher peak historical severity (an unauthenticated 2021 RCE, KEV-listed) because, per [THREAT_MODEL.md T2-C](THREAT_MODEL.md), nearly all of its actionable remediation reduces to a fast, conclusive dependency-version comparison rather than open-ended slice auditing — it is evidence-dense but audit-shallow, which the instruction to rank "based on actual evidence" for *further work* argues against prioritizing here.

---

No testing has been performed against any instance. Stopping here per instruction.
