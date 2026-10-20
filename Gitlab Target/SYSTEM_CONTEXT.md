# SYSTEM_CONTEXT.md — GitLab (self-managed instance / gitlab-org/gitlab)

Scope authority: [TARGET_SELECTION.md](TARGET_SELECTION.md) — testing target is **my own GitLab instance** (GDK for exploration, an Omnibus/Docker release build for reproduction), never gitlab.com. Everything below is derived from reading the public source at `gitlab.com/gitlab-org/gitlab` (checked out locally at commit tag `v19.5.0-pre`, plus `gitlab-org/gitlab-shell`, `gitlab-workhorse`, `gitlab-org/gitaly` references), not from any live testing. No intrusive testing has been performed.

Repo layout referenced below: `app/`, `lib/`, `ee/`, `gems/gitlab-http/`, `workhorse/` (Go) inside the main `gitlab` repo; separate repos `gitlab-shell` (Go, SSH entry), `gitaly` (Go, git RPC backend), `gitlab-pages` (Go, static hosting), `gitlab-runner` (Go, CI executor).

## 0. High-level component map

```
attacker (internet)
  │
  ├─► HTTPS :443/:80 ──► gitlab-workhorse (Go reverse proxy) ──► Puma/Rails (gitlab-org/gitlab) ──► PostgreSQL, Redis, Gitaly (gRPC), Elasticsearch/Zoekt, object storage (S3-compatible)
  │                              │                                   │
  │                              ├─► Gitaly (git operations, gRPC)   ├─► Sidekiq (async jobs, same Rails codebase, shares Redis queue)
  │                              └─► direct large-object streaming   └─► ActionCable (websockets) for pipelines/issues live updates
  │
  ├─► SSH :22 ──► gitlab-shell (Go) ──► internal API (Rails, shared-secret authenticated) ──► Gitaly
  │
  ├─► Registry API (docker) ──► container registry (separate Go service) ──► Rails internal API for token auth
  │
  └─► GitLab Pages (Go static file server, custom domains + wildcard subdomain) ── reads from object storage, no direct DB access
```

Rails is the trust anchor for almost everything: authn/authz, business logic, webhooks, imports, GraphQL/REST APIs. Workhorse, gitlab-shell, Gitaly and Pages are “dumb” front doors that authenticate to Rails via a shared secret / short-lived JWT and otherwise trust Rails’ decisions.

---

## 1. Public applications / 2. APIs — entry points

| Entry point | Code | Notes |
|---|---|---|
| Web app (Rails views + Vue SPA fragments) | `app/controllers/*` (`app/controllers/application_controller.rb` is the base) | Session-cookie authenticated, CSRF-protected (Rails `protect_from_forgery`) |
| REST API v4 | `lib/api/*.rb` (Grape), mounted at `/api/v4` — `api.rb` lists ~180 resource files (`lib/api/projects.rb`, `merge_requests.rb`, `users.rb`, `ci/*`, `packages/*`, etc.) | Token-, session-, job-token-, or OAuth-authenticated per endpoint via `route_setting`/`before` blocks |
| GraphQL API | `app/graphql/gitlab_schema.rb`, single POST endpoint `/api/graphql` | Depth/complexity limited (`DEFAULT_MAX_DEPTH=15`, `AUTHENTICATED_MAX_DEPTH=20`, complexity 200–300), per-field authorization via `authorize` declarations in `app/graphql/types/*` |
| Internal API (gitlab-shell, Workhorse, Gitaly, KAS, mailroom) | `lib/api/internal/*.rb` mounted under `/api/v4/internal/*` | Authenticated by **shared secret**, not user credentials — see §7 |
| Git over HTTP(S) | routed through Workhorse (`workhorse/internal/upstream/routes.go`, patterns `gitProjectPattern`) straight to Gitaly after a Rails `git_access` check | |
| Git over SSH | `gitlab-shell` binary, keys resolved via internal API `/api/v4/internal/authorized_keys` and `/api/v4/internal/allowed` | |
| Container Registry API | separate `container-registry` Go service, auth via JWT minted by Rails (`lib/api/internal/base.rb`-style flow via `container_registry_authentication_service`) | out of primary code scope here |
| Pages | `gitlab-pages` Go binary, serves object-storage content per custom domain | |
| Webhook receivers (inbound) | none — GitLab only sends outbound webhooks; inbound integration endpoints exist per integration (Jira Connect `app/controllers/jira_connect/*`, Slack, etc.) | |
| ActionCable websockets | `/-/cable`, used for pipeline/board live updates | Authenticated via Rails session (Devise warden) |

---

## 2/4/5. Authentication mechanisms and session/token architecture

`lib/gitlab/auth/auth_finders.rb` (`AuthFinders` module, mixed into `API::Helpers` and controllers) enumerates every credential type the app will accept on a single request, in priority order roughly:

1. **Session cookie** (`find_user_from_warden`) — Devise/Warden, backing store is the Rails session (cookie store or Redis-backed, `same_site_cookies` middleware present at `lib/gitlab/middleware/same_site_cookies.rb`).
2. **Personal Access Token (PAT)** — header `PRIVATE-TOKEN` or `private_token` param (`find_user_from_personal_access_token`), scope-checked (`Gitlab::Auth::API_SCOPES`, etc., defined in `lib/gitlab/auth.rb`).
3. **OAuth2 Bearer token** (Doorkeeper) — `find_user_from_bearer_token` → `find_user_from_access_token`, scope-checked against `Doorkeeper.configuration.scopes`.
4. **CI job token** — header `JOB-TOKEN` / param `job_token`, `find_user_from_job_token`, max size capped (`MAX_JOB_TOKEN_SIZE_BYTES = 8192`); this is the identity used by CI jobs to call back into the API — cross-project access is restricted by the CI/CD job-token allowlist (`ci_job_token_scope` feature, `Gitlab::Auth::CI_JOB_USER`).
5. **Deploy token** — header `Gitlab-Deploy-Token` / basic-auth, `deploy_token_from_request`, scoped to a project/group and read/write repo or registry only (never a full user).
6. **LFS token / basic-auth git password** — for git-over-http.
7. **Feed token / static-object token** — long-lived tokens embedded in RSS/calendar/atom URLs and “raw” file links, deliberately narrow scope (`find_user_from_feed_token`, `find_user_from_static_object_token`).
8. **Runner registration/auth token** — `find_runner_from_token`, separate identity space from users entirely (`Ci::Runner`).
9. **DPoP tokens** (`lib/gitlab/auth/dpop_token.rb`) — sender-constrained token binding, newer addition.
10. **Composite identity** (`resolve_composite_identity_user`) — used for Duo/agentic flows where a service account acts *as* a human; a boundary worth extra attention (impersonation semantics baked into normal request auth).

**Session model:** classic server-validated session (Warden), admin-mode is a *separate* elevation flag layered on top of a normal session (`lib/gitlab/auth/current_user_mode.rb`): `admin_mode?` requires `user.can_access_admin_area?` **and** either a privileged runtime (Sidekiq/rails console) or `session_with_admin_mode?`, which expires after `MAX_ADMIN_MODE_TIME = 6.hours` and must be re-entered with password (`enable_admin_mode!(password:)`). This is a step-up-auth boundary distinct from “is this user an admin” — a bug that conflates `user.admin?` with `admin_mode?` anywhere is a privilege-escalation-relevant pattern to grep for.

**Two-factor / OTP:** `devise-two-factor` gem, WebAuthn support; `lib/gitlab/auth/otp/*`.

**SSO/Federation:** SAML (`ruby-saml` + `omniauth-saml`), OIDC (`omniauth_openid_connect`, plus GitLab acting as an OIDC *provider* via `doorkeeper-openid_connect`), LDAP (`gitlab_omniauth-ldap`), Google/GitHub/Azure/Salesforce/Atlassian/Auth0/Alicloud OmniAuth strategies (`app/controllers/omniauth_callbacks_controller.rb`). `ruby-saml`/`rexml` are both gems with a history of parser-level XML vulnerabilities upstream (XXE/signature-wrapping classes) — version pins (`ruby-saml ~> 1.18`, `rexml ~> 3.4.0`) are worth diffing against the CVE history of those gems specifically.

---

## 3. Authorization model

`app/policies/*` (105 files) implement `DeclarativePolicy` (`app/policies/base_policy.rb` is the root). Key structure:
- **Conditions** are boolean predicates memoized per (user, subject) pair — e.g. `condition(:admin)`, `condition(:blocked)`.
- **Rules** (`rule { can!/cannot! :some_ability }`) compose conditions; EE overrides and extends CE policies via `prepend_mod_with`-style patterns (grep for `ee/app/policies/ee/*`).
- Every model that exposes an ability check does so via `Ability.allowed?(user, :ability, subject)`, which resolves to the corresponding `*Policy` class (`ProjectPolicy`, `GroupPolicy`, `IssuePolicy`, …).
- GraphQL types declare `authorize :some_ability` per field/type (`app/graphql/types/*`), and REST endpoints call `authorize!` helpers — **the two code paths are independently maintained**, so a REST endpoint and GraphQL field exposing the same underlying model are two separate places a check can be missing or inconsistent (classic bug class in this codebase’s own disclosed history: GraphQL under-authorization vs REST).
- Visibility levels (private/internal/public) cascade from group → project and are enforced both at the policy layer and at the query layer (`Project.public_or_visible_to_user`) — a raw `Project.find`/association traversal that skips the scope method is an IDOR pattern.
- Confidential issues/epics, protected branches/environments/tags, and CI/CD job-token project-allowlists are all *additional* authorization layers on top of the base project membership model — each has its own bypass history upstream (see CVE-2026-86340/86341 in TARGET_SELECTION.md, “protected environment approval bypass”).

---

## 4. Tenant boundaries

GitLab’s multi-tenancy is **namespace/group/project scoping inside one shared database and one shared Rails/Gitaly/Sidekiq fleet** (not per-tenant containers). The trust boundary is enforced entirely in application code:
- Every ActiveRecord model with tenant data is expected to be scoped through `Project`/`Namespace`/`Organization` (`app/models/concerns/current_organization_helpers`, `set_current_organization`), and Sidekiq jobs get "sharding" context attached (`sidekiq_shard_awareness_validation.rb` middleware).
- Cross-tenant leakage classes to watch for: GraphQL resolvers that accept a global ID and fetch-then-authorize (race between fetch and authorize, or fetch of the wrong type via GlobalID confusion), Sidekiq workers that receive a raw project/user ID as an argument and don't re-check authorization at execution time (jobs are queued by one actor and run by a generic worker fleet — the *authorization decision made at enqueue time may be stale by execution time*), and Elasticsearch/Zoekt search indices which must independently filter by permission (search-index permission-drift is a known upstream bug class — CE search backends re-derive ACLs at query time from `IidsFinder`/`Search::*` scopes).
- Organizations (`app/controllers/organizations`, newer top-level construct above groups) are a second/newer tenant boundary layered above namespaces — being newer code, this is comparatively less battle-tested.

---

## 5. Plugin/extension boundaries

- **CI/CD includes and templates**: `.gitlab-ci.yml` `include:` (local/remote/template), CI job execution runs in a Runner sandbox (separate trust domain — the “sandbox” for arbitrary code is the *Runner’s executor*, not Rails; Rails only orchestrates). CI/CD Components (`.gitlab-ci.yml` component repos) and Pipeline Execution Policies (`ee/`) are newer plugin-like surfaces — CVE-2026-79708 above (“Scheduled Pipeline Execution Policy test privilege escalation”) sits exactly here.
- **Integrations framework**: `app/models/integrations/*` (Slack, Jira, PagerDuty, generic webhook-based integrations) — each integration is effectively a mini-plugin with its own inbound/outbound trust boundary; `app/models/concerns/integrations/has_web_hook.rb` wires integrations to the same webhook-SSRF-guarded HTTP client (§13).
- **GitLab Duo / Agent Platform / MCP**: `lib/api/helpers/mcp/*`, agent tool definitions — this is the newest, least-hardened plugin surface (tool definitions are effectively an extension point that can be manipulated via prompt injection; note the *large* “known prompt injection” exclusion list in the program policy — the bounty program already treats most of this class as out of scope unless it crosses a security boundary).
- **OAuth Applications** acting as GitLab API consumers are also a “plugin” boundary from GitLab’s perspective — a malicious/compromised OAuth app is scoped by Doorkeeper scopes only.

---

## 6. File upload/download paths

Two upload transports:

1. **Direct Rails multipart** for small forms.
2. **Workhorse-accelerated upload** (the norm for anything large: repo uploads, package registry, artifacts, avatars, LFS): the browser/CI client streams the multipart body to **Workhorse**, which peels off file parts, writes them to a tempfile (or directly to object storage if "direct upload" is enabled), and replaces the file part in the multipart body with a small **JWT-signed** reference (`Gitlab-Workhorse-Multipart-Fields` header, decoded in `lib/gitlab/middleware/multipart.rb`). Rails then trusts that JWT blindly for the file's local path.

Sensitive sink and validated invariant:
- `lib/uploaded_file.rb#from_params` takes the JWT-decoded `path` param, resolves it with `File.realpath` (so no `..` survives) and requires `allowed_path?` to match one of a **fixed allowlist of upload directories** (`Dir.tmpdir`, `FileUploader.root`, package/artifact/LFS/terraform-state upload roots, `public/uploads/tmp`). This is the load-bearing anti-path-traversal check for the entire upload subsystem — **its correctness depends entirely on the JWT actually being signed only by Workhorse with the true Workhorse secret** (`Gitlab::Workhorse` HMAC/JWT secret file, `/etc/gitlab/gitlab-secrets.json` in a real deployment). If that secret is ever guessable, disclosed, or the JWT verification skips issuer/expiry (`API_REQUEST_JWT_VALIDITY = 90.seconds`, `Gitlab-Workhorse-Api-Request` header), arbitrary local file read/registration becomes possible. This is the single highest-value invariant in the file-upload flow.
- Route-level allowlisting also happens in Workhorse itself (`workhorse/internal/upstream/routes.go`): only specific path patterns (`requestBodyUploader`, `mimeMultipartUploader`, `tempfileMultipartProxy`) are wired to accept large/multipart bodies, each with its own body-size limit (e.g. Terraform state lock capped at 4 KB, GraphQL body capped at 20 MB) — a route that *should* have a body-size cap but doesn't would be a DoS-adjacent (mostly out-of-scope per policy) or resource-exhaustion finding.

Download paths of interest: `send_url`, `send_git_blob/archive/diff`, `senddata`/`sendfile` Workhorse packages — these implement **X-Sendfile-style acceleration**, where Rails computes an authorization decision and hands Workhorse an *already-approved* signed reference to stream from disk/object storage/gitaly. The invariant to check anywhere this pattern is used: the signed reference must encode enough of the original authorization context (which repo, which ref, which user) that Workhorse can't be tricked into serving a different resource than the one Rails authorized (parameter confusion / signed-blob substitution).

---

## 7. Service-to-service boundaries (Workhorse/gitlab-shell/Gitaly ↔ Rails)

Internal API `lib/api/internal/base.rb` — `before { authenticate_by_gitlab_shell_token! }` (`lib/api/helpers.rb:397`) calls `Gitlab::Shell.verify_api_request(headers)`, i.e. **a single shared secret** (`Gitlab::Shell.secret_token`, stored in `.gitlab_shell_secret` / `gitlab-secrets.json`) authenticates gitlab-shell → Rails for every SSH git operation and key lookup. `shellhorse.rb` additionally accepts either that shell secret **or** a Workhorse JWT (`authenticate_by_gitlab_shell_or_workhorse_token!`). Compromise of this one secret is equivalent to full impersonation of the SSH front door (arbitrary `gl_id`/repo access decisions). This secret is out of remote-attacker reach normally (it's a local file on the app server) — relevant mainly if there's a way to read arbitrary files or environment/config from within the Rails app (path traversal, SSTI, deserialization) that would let an attacker pivot from "web bug" to "impersonate gitlab-shell."

Gitaly is reached via gRPC with its own `gitaly_context`/token (`add_gitaly_context`), and the Rails app is the *only* thing that decides whether a given git operation is allowed (`access_check_result` → `Gitlab::GitAccessResult::Success/CustomAction`); Gitaly itself does no authorization — it trusts whatever repository path and options Rails/gitlab-shell hand it. A bug that lets an attacker control the `relative_path`/`gl_repository` values passed into a Gitaly RPC (without going through the normal access-check code path) would be a repository-confusion / cross-project read bug.

---

## 8. Password reset / account recovery

`app/controllers/passwords_controller.rb` (Devise `recoverable`). Points worth checking against the actual running instance rather than just source: token generation entropy (Devise default is a secure random token, hashed at rest), whether the reset endpoint leaks account existence (timing or response-content oracle — explicitly **out of scope** per the bounty policy unless chained), and whether 2FA/WebAuthn is required again post-reset (account-recovery-bypasses-2FA is a classic high-value bug class here). `confirmations_controller.rb` (email confirmation) and `registrations_controller.rb` (self-signup, only relevant if enabled — GitLab explicitly notes self-managed instances mostly disable this, hence unauthenticated bugs are scored more severely per the program's platform-standards deviation).

---

## 9. Administrative functionality

`app/controllers/admin/*` — gated by `authenticated_as_admin!`/`admin_mode?` (see §2 session model). Two-layer check to keep in mind when hunting: (a) is the controller/action guarded by an authorization filter at all (missing `before_action :authenticate_admin!` is the classic omission bug), and (b) does that filter check `admin_mode?` (step-up) or only `user.admin?` (any authenticated admin-flagged user, even mid-session before entering admin mode) — code that checks the latter where it should check the former is a real, source-verifiable bug pattern to grep for (`current_user.admin?` used directly instead of `Gitlab::Auth::CurrentUserMode.new(current_user).admin_mode?` or the `authenticated_as_admin!` helper).

---

## 10/11/12. Background workers, message queues, scheduled jobs, deserialization, template rendering

- **Sidekiq**: `app/workers/*` (484 classes including EE), `ApplicationWorker` concern (`app/workers/concerns/application_worker.rb`) — every worker declares a `feature_category`, `queue`, `urgency`, `data_consistency`. Job arguments are serialized to Redis as JSON (Sidekiq default) — the trust boundary is: **anything reachable as a Sidekiq job argument is effectively attacker-reachable if any web-facing code path lets a user influence what gets enqueued** (e.g., enqueuing a job with a URL, path, or ID the user controls, where the worker later performs a privileged filesystem/network operation without re-validating). `gitlab-sidekiq-fetcher`/reliable-fetch is vendored (`vendor/gems/sidekiq-reliable-fetch`).
- **Scheduled jobs**: `sidekiq-cron` gem; cron schedules defined in `config/initializers` / EE cron initializers — a worker that is safe when triggered by a legitimate internal caller but is *also* reachable via a public-facing "trigger now" action (e.g. a rake task or admin button that enqueues it) needs its authorization re-checked at that trigger point, not just trusted because "it's just a cron job."
- **Deserialization**: Import/Export (`lib/gitlab/import_export/*`) is the standout risk area — an attacker-supplied project/group export tarball is parsed and used to reconstruct database records. `lib/gitlab/import_export/config.rb` uses `YAML.safe_load_file(..., permitted_classes: [Symbol])` (good — not full `YAML.load`), and `attributes_permitter.rb` explicitly allow-lists which attributes/relations can be set from the imported JSON (defense against mass-assignment via a crafted export). `decompressed_archive_size_validator.rb` and `file_importer.rb` guard against zip-bomb/path-traversal in the extracted tree (matches the `path_traversal.rb`/`check_path_traversal` grep hits found across `lib/gitlab/import_export`). This whole subsystem is high-value: it is explicitly one of the only places an authenticated-but-low-privilege user hands the server a complex, attacker-authored structured file that gets walked and partially trusted.
- **Template rendering**: Markdown pipeline (`lib/banzai/*`, `gitlab-markup`, `commonmarker`, `redcarpet`-era filters mostly replaced) sanitizes with `nokogiri`; the recent CVE-2026-78252 ("XSS in Markdown JSON table renderer") shows the renderer pipeline is still an active bug surface — any new Banzai filter or Markdown extension is worth checking for sanitizer bypass before/after the `Sanitization` filter runs relative to filters that interpolate raw HTML.

---

## 13. Webhooks (outbound) — SSRF chokepoint

Model: `WebHook < ApplicationRecord` includes `WebHooks::Hook` concern (`app/models/concerns/web_hooks/hook.rb`), which validates `:url` with `public_url: true` → `PublicUrlValidator` (`app/validators/public_url_validator.rb`, defaults `allow_localhost: false, allow_local_network: false`) → `AddressableUrlValidator` (`app/validators/addressable_url_validator.rb`) → `Gitlab::HTTP_V2::UrlBlocker.validate!` (`gems/gitlab-http/lib/gitlab/http_v2/url_blocker.rb`, 556 lines).

The actual send happens in `app/services/web_hook_service.rb#execute` via `Gitlab::HTTP.post(url, ...)` — **note the documented, deliberate gap**: `AddressableUrlValidator::BLOCKER_VALIDATE_OPTIONS` disables `dns_rebind_protection: false` for the *model validation* pass (comment explicitly says this is to avoid breaking saves when a URL isn't resolvable yet), meaning the strict IP-based check (loopback/private-network/link-local exclusion, resolved via `Resolv`/`IPAddr`, `validate_link_local`, `ipv6_excluded_by_no_proxy?`) is what actually runs **at request time inside `Gitlab::HTTP`**, not necessarily identically at save time. Any code path that sends an outbound request using a stored URL **without** going back through `Gitlab::HTTP`'s enforcement (e.g., a custom `Net::HTTP` call, a gem that does its own DNS resolution, or a redirect followed by the underlying HTTP client rather than by `UrlBlocker`) is the textbook SSRF bug shape for this codebase — this exact bug class (webhook/integration SSRF, including via redirect-following) has a long disclosed history on this program and is precisely the kind of "business impact = read cloud-metadata/internal service" finding the bounty rewards at High/Critical. `dns_rebind_protection` re-resolves and pins the IP actually connected to (`enforce_uri_hostname`) specifically to defeat TOCTOU DNS rebinding between the check and the connect.

Custom headers (`custom_headers` validation errors surfaced in `WebHooks::CreateService`) and URL variables (`url_variables` JSON-schema-validated) are additional attacker-influenced fields worth checking for header/CRLF injection into the outbound request.

---

## 14. OAuth/OIDC

GitLab is both an OAuth2/OIDC **client** (all the OmniAuth strategies, §2) and an OAuth2/OIDC **provider** (Doorkeeper + `doorkeeper-openid_connect`, endpoints `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/userinfo`, `/.well-known/openid-configuration` per `well_known_controller.rb`). Workhorse routes these directly (`authorizeRoute`, `tokenRoute` in `routes.go`) with no special body-size handling beyond default, meaning `/oauth/token` is a normal API-shaped attack surface (grant-type confusion, PKCE downgrade, redirect_uri validation strictness, scope escalation via `optional_scopes`/`ADMIN_SCOPES` in `lib/gitlab/auth.rb`) — worth diffing GitLab's Doorkeeper config for custom grant types (`doorkeeper-device_authorization_grant` is present — device-code flow, a historically bug-prone OAuth extension: check for missing user-code binding/polling-rate limits).

---

## 15. Native bindings / non-Ruby components in the trust chain

- **Gitaly**, **gitlab-shell**, **gitlab-workhorse**, **gitlab-pages**, **gitlab-runner** are all Go; **KAS** (Kubernetes Agent Server) also Go. Memory-safety bugs are less likely (Go), but argument-injection into `git` subprocess calls (Gitaly shells out to the real `git` binary) is the classic bug class — e.g., a ref/path name that begins with `-` being interpreted as a git CLI flag. Look at Gitaly's command builder allowlisting (not in this sparse checkout; would need the separate `gitaly` repo) for `--` separators before user-controlled ref/path arguments.
- **libgit2/rugged** is no longer used (GitLab moved fully to Gitaly/go-git for most paths) — verify against `Gemfile` before assuming otherwise on the actual installed version.
- **Elasticsearch/Zoekt** (Advanced Search) — CVE-2026-88765 above ("Buffer overflow in Unicode conversion wrapper... Advanced Search indexing") shows this indexing pipeline touches non-Ruby/native code paths (likely the ICU/Unicode conversion layer) with attacker-influenced content (repo file contents, commit messages) as input.

---

## 16. External integrations / storage / secrets

- **Object storage**: S3-compatible (AWS S3, GCS, Azure via `fog`), configured per-uploader (`JobArtifactUploader`, `LfsObjectUploader`, `Packages::PackageFileUploader`, etc.), each with a `workhorse_upload_path`/`workhorse_local_upload_path` — these are exactly the allowlist entries consulted by `UploadedFile.allowed_path?` (§6). Direct-upload mode changes the trust model: when `direct_upload: true`, Workhorse talks to object storage directly and only hands Rails a `remote_id`, which is a different code path (`UploadedFile.from_params` takes the `remote_id` branch, skipping the local-path allowlist entirely) — worth checking whether `remote_id` is validated to belong to the expected bucket/prefix before Rails "adopts" it as a real upload record (an attacker who can get a job token or forge the multipart JWT could otherwise register an arbitrary pre-existing object-storage key as their own upload).
- **Secrets**: `Gitlab::Shell.secret_token`, Workhorse JWT signing secret, Doorkeeper application secrets, CI/CD variables (masked/protected), `ee/` secret-detection features — all ultimately backed by `/etc/gitlab/gitlab-secrets.json` on a real install; source-review can only identify *how* a secret is used/verified, not extract it, which is expected and correct.
- **CI/CD variables**: incorrect-authorization CVE-2026-13210 above is exactly the environment-variable-scope boundary (`app/models/ci/variable.rb`, environment-scoped and protected-branch-scoped variables) — this is a recurring bug class (masked variable exposure via job log, cross-environment variable leakage).

---

## 17. Sandbox / privileged execution boundaries

- **CI job execution** is the "real" sandbox in this system, but it lives in `gitlab-runner`/the executor (Docker/K8s/Shell), outside the Rails codebase — from Rails' perspective the trust boundary is *what gets fed into the job* (CI/CD variables, job token scope) and *what the job is allowed to call back into the API for*, not the sandbox escape itself (which would be a `gitlab-runner` or container-runtime bug, likely out of this program's primary scope unless it maps to a GitLab-controlled config).
- **Admin mode** (§2/§9) is GitLab's own "privileged execution" step-up boundary inside the web app.
- **Composite identity / Duo agent execution** (§2 item 10) is the newest privileged-boundary concept — a service identity executing *as* a human but constrained to that human's permissions; logic bugs here (the constraint not being applied on some code path) are a natural place to look for privilege escalation in the AI feature surface, independent of prompt-injection (which is largely out of scope per policy).

---

## Prioritized flow diagrams (attacker → sink)

### A. Webhook SSRF (highest-confidence, well-precedented bug class here)

```
attacker (any user who can create a project/group webhook or integration, or an admin-configurable system hook)
  ↓ attacker-controlled input: webhook "URL" field (+ custom headers, url_variables)
  ↓ trust boundary: WebHook#url stored in DB, later fetched by WebHookService without further human review
  ↓ validation (creation time): PublicUrlValidator → AddressableUrlValidator → Gitlab::HTTP_V2::UrlBlocker.validate!
        (allow_localhost:false, allow_local_network:false, but dns_rebind_protection:false at THIS stage)
  ↓ authorization check: hook belongs to a project/group the user can admin (Maintainer+/Owner) — standard project-scoped check
  ↓ business logic: WebHooks::CreateService / async trigger (push, MR, pipeline events) enqueues WebHookService
  ↓ sensitive sink: Gitlab::HTTP.post(url, ...) inside WebHookService#execute — enforcement here DOES set dns_rebind_protection:true and re-validates
  ↓ expected invariant: every code path that dereferences a stored/attacker-influenced URL goes through Gitlab::HTTP (which wraps UrlBlocker with rebind protection), never a bare Net::HTTP/open-uri/other HTTP client, and redirects are re-validated per hop, not just the initial host
  ↓ victim/resource: internal network services, cloud metadata endpoint, other tenants' internally-reachable services
```
Where to look for the actual bug (not yet tested): any *newer* integration, importer ("import by URL" for projects/repos/Gitea/GitHub/Bitbucket), avatar-by-URL, custom CI/CD component source URLs, or dependency-proxy/remote-mirror URL fields that might build their own HTTP client instead of reusing `Gitlab::HTTP`.

### B. Workhorse-accelerated upload path confusion

```
attacker (any user who can reach an upload-accepting endpoint: issue attachment, avatar, package registry, artifact upload)
  ↓ attacker-controlled input: multipart file field name/content; potentially the JWT if the Workhorse secret were ever exposed
  ↓ trust boundary: Workhorse (trusted infra) signs a JWT asserting {path, name, type, size, remote_id} for the tempfile it created
  ↓ validation: lib/gitlab/middleware/multipart.rb decodes JWT (Gitlab::Workhorse.decode_jwt_with_issuer) → UploadedFile.from_params
        → File.realpath(path) + allowed_path?(path, allowlist) — must resolve inside one of a fixed set of upload roots
  ↓ authorization check: the *endpoint's* normal authz (e.g., can this user upload to this project) — separate from the path check above
  ↓ business logic: controller/service persists an Upload/JobArtifact/PackageFile record pointing at that path or remote_id
  ↓ sensitive sink: file is later served back (send_file/senddata) or ingested (package registry parses it, CI ingests artifacts)
  ↓ expected invariant: the realpath-resolved file path can never fall outside the declared allowlist roots, and a `remote_id`-based (direct-upload) record can never be forged to point at an object-storage key the current request didn't itself just create
  ↓ victim/resource: arbitrary local file disclosure (if allowlist check is bypassable) or object-storage object confusion (if remote_id isn't scoped/verified)
```

### C. GraphQL vs REST authorization drift

```
attacker (any authenticated user, sometimes unauthenticated for public resources)
  ↓ attacker-controlled input: GraphQL query selecting a field/type also exposed via REST, or vice versa
  ↓ trust boundary: same underlying ActiveRecord model, two independent authorization declarations
        (Grape endpoint's authorize!/before block vs GraphQL type's `authorize :ability` / resolver-level check)
  ↓ validation: GraphQL depth/complexity limits (not a security control here, just cost control)
  ↓ authorization check #1 (REST): usually a project/group membership + Ability.allowed? check in the Grape endpoint or a Finder scope
  ↓ authorization check #2 (GraphQL): `authorize` on the Type/Field, or manual check inside a custom Resolver#resolve
  ↓ business logic: Finder classes (app/finders/*) are supposed to be the single source of truth for "what can this user see" — a resolver that queries the model directly instead of via the Finder is the highest-suspicion pattern
  ↓ sensitive sink: field value returned in API response
  ↓ expected invariant: identical effective authorization regardless of which API surface (REST/GraphQL) is used to reach the same data
  ↓ victim/resource: cross-project/cross-namespace data disclosure (confidential issues, private repo metadata, other users' tokens/emails)
```

---

## What was deliberately not done

- No requests were sent to gitlab.com or any live instance.
- No credentials, secrets, or JWTs were fabricated or tested.
- Gitaly/gitlab-shell/gitlab-pages source (separate repos) was referenced from memory/public knowledge, not re-cloned, given time budget — should be pulled before deep-diving §7/§15 further.
- ee/ (Enterprise Edition) directory was included in the checkout but only spot-checked; EE-only features (SAML group sync, protected environment approvals, Duo/agentic tooling) deserve their own pass before intrusive testing begins there.

## Next step (not yet started)

Stand up a local GDK instance, and pick **one** flow above (recommend A: webhook/integration SSRF, since it's concrete, well-scoped, explicitly bounty-eligible, and has a clear "expected invariant" to falsify) to trace end-to-end against a running instance before writing any exploit code. Waiting for instruction to proceed.
