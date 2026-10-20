# SECURITY_INVARIANTS.md — GitLab (self-managed instance)

Scope authority: [TARGET_SELECTION.md](TARGET_SELECTION.md) — no testing performed; this is source analysis against the local checkout at `src/gitlab` (commit tag `v19.5.0-pre`, sparse-checked-out as described in [SYSTEM_CONTEXT.md](SYSTEM_CONTEXT.md)) plus the evidence in [HISTORICAL_VULNERABILITY_MODEL.md](HISTORICAL_VULNERABILITY_MODEL.md) and the prioritization in [THREAT_MODEL.md](THREAT_MODEL.md).

Method: for every historical vulnerability class, I extracted the general invariant that was violated, the assumption the vulnerable code made, and the exact failure condition. I then searched the **current** codebase for other places the same invariant is relied on — by searching for the semantic shape of the pattern (e.g. "an HTTP client call site outside the vetted wrapper," "a path built from a request parameter reaching a filesystem call," "an ID-keyed lookup with no surrounding scope") rather than grepping for the names of the original vulnerable functions, most of which no longer exist under those names. Where a search returned a concrete file, it is cited as a **candidate location** — this means "this is architecturally the right shape to check by hand or with a live instance," not "this is confirmed vulnerable." No exploitation was attempted.

Invariants are ordered by combined priority (historical frequency × attack surface × privilege boundary × exploitability × impact, per the instruction), highest first.

---

## INV-01 — Redirect/URL construction never yields a cross-origin destination from same-origin-only input

**Invariant:** A path or URL built from a route/parameter segment that the code assumes is relative and same-origin can never be interpreted by the browser or an HTTP client as absolute/cross-origin — and no security-sensitive value (CSRF token, OAuth access token, session identifier) may be sent to a destination that hasn't been validated against this invariant.

**Why it matters:** This is GitLab's single most-recurring architectural flaw in the historical record — the same root cause (a leading/embedded `//` or an unescaped path segment producing a protocol-relative or otherwise absolute URL) produced disclosed bugs in **2017, 2022 (×1 original + ×1 acknowledged-incomplete fix), and 2024 (×2)** — five distinct instances across seven years, each time patched narrowly enough that a structurally identical route elsewhere kept the bug alive.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 3](HISTORICAL_VULNERABILITY_MODEL.md) — HackerOne #221432 (2017, CSRF-token leak via `location.pathname` + `//attacker.com`), CVE-2022-2250 (open redirect via undeduplicated `//`), GitLab's own issue [#377810](https://gitlab.com/gitlab-org/gitlab/-/issues/377810) documenting that the CVE-2022-2250 fix (a `gsub(%r{\/{2,}}, '/')` in `lib/gitlab/jira/dvcs.rb`) didn't cover routes that *themselves* prepend a slash to a decoded path (`config/routes/project.rb`, `config/routes/repository_deprecated.rb`), and CVE-2024-4283/CVE-2024-4612 (2024, "open redirect ... account takeover by breaking the OAuth flow").

**Relevant components:** Rails route definitions that interpolate a decoded path segment (`config/routes/*.rb`), any controller `redirect_to` call built from request data, frontend JS that derives a request URL from `location.pathname`/`document.location`, the OmniAuth/OAuth callback and Jira DVCS integration flows.

**Potential violation patterns:**
- A route helper or controller builds a URL/path by string concatenation or interpolation of a parameter, rather than using Rails' own escaping/routing helpers throughout.
- A "deduplicate slashes" or single-pattern regex fix is applied at *one* call site but the same raw parameter is also consumed by a sibling route/controller that skips the fix (exactly what happened in #377810).
- Any `redirect_to` (or JS `window.location =` equivalent) that isn't restricted to a relative path or an explicit allowlist of hosts, especially anywhere positioned after an OAuth authorization step (where the redirect target carries a token in the fragment/query).
- CSRF-token-bearing AJAX/GraphQL client code that derives its request URL from page-relative state rather than a hardcoded/allowlisted origin.

**Candidate locations (current source):**
- `config/routes/project.rb` and `config/routes/repository_deprecated.rb` — named explicitly in GitLab's own #377810 as still containing the general "route prepends a slash to a decoded path" shape as of that issue; worth re-checking on the current instance since these are the exact routes the acknowledged-incomplete fix didn't cover.
- `lib/gitlab/jira/dvcs.rb` — site of the original CVE-2022-2250 fix; check whether the fix generalized to canonicalization or is still the narrow `gsub` de-duplication described in #377810.
- OmniAuth/OAuth callback handling (`app/controllers/omniauth_callbacks_controller.rb`, `app/controllers/oauth/*`) — any `redirect_uri`/`state`/`continue`-style parameter that isn't validated against Doorkeeper's registered-redirect-URI allowlist before being used for a post-auth redirect.
- Any frontend module still building request URLs from `location.pathname`/`document.location` string concatenation, the same shape as the original 2017 report — a targeted `location.pathname` / `window.location` grep across `app/assets/javascripts` was not completed in this pass due to time budget and should be done before intrusive testing.

**Required attacker capability:** none-to-low — most historical instances required only getting a victim to click a crafted link (or, in the 2019 CSRF case, load an attacker page); the 2017 instance additionally required the ability to register a crafted namespace name.

**Potential impact:** Critical when chained to OAuth-token theft or CSRF-token theft → full account takeover or arbitrary state-changing action as the victim; Medium on its own (bare open redirect).

---

## INV-02 — A file/repository path resolved from user input can never escape its intended root, regardless of nesting depth or encoding

**Invariant:** Any code that turns a request parameter (or a chain of nested route segments) into a filesystem or repository path must canonicalize that path and confirm it stays within an explicit allowed root — encoding, nesting depth, and traversal-sequence obfuscation must not be able to defeat that confinement.

**Why it matters:** This class has produced two **Critical, unauthenticated, CVSS-10.0** vulnerabilities three years apart (2023, 2026) in file/repository-serving code, and [SYSTEM_CONTEXT.md §6](SYSTEM_CONTEXT.md) already identified that GitLab uses **two architecturally different defenses** for what should be the same invariant: the upload-ingest path uses `File.realpath` + a fixed allowlist (`lib/uploaded_file.rb#allowed_path?`), while general path-traversal defense elsewhere uses `Gitlab::PathTraversal`, a **regex blocklist** (see below), which is a structurally weaker pattern (deny-known-bad vs. canonicalize-and-allow-known-good).

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 2](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2023-2825 (uploads path traversal via ≥5-level group nesting, `/:repo/uploads/:id/:file`) and CVE-2026-85706 (repository-commits API path traversal, cited in [TARGET_SELECTION.md](TARGET_SELECTION.md), CVSS 10.0, CISA KEV).

**Relevant components:** `lib/gitlab/path_traversal.rb` (the central helper), `lib/uploaded_file.rb` (the separate, stronger allowlist mechanism used only for Workhorse-accelerated uploads), any controller/API endpoint that reads a file/blob/attachment/artifact by a path-shaped parameter.

**Potential violation patterns:**
- A code path calls `Gitlab::PathTraversal.path_traversal?` (the boolean-returning form) but **doesn't actually block the request when it returns `true`** — a straightforward "checked but not enforced" bug, distinct from and easier to introduce than a broken check.
- A code path decodes the parameter a **second time** after `check_path_traversal!` has already run its single `Gitlab::Utils.decode_path` pass — double-encoded traversal sequences (`%252e%252e%252f`) would survive the first check and only become `../` after a second, later decode.
- The regex (`PATH_TRAVERSAL_REGEX` — `\A(\.{1,2})\z|\A\.\.[/\\]|[/\\]\.\.\z|[/\\]\.\.[/\\]`) requires `..` to be bounded by `/`, `\`, or a string edge; any traversal-equivalent construction that doesn't match this exact shape (alternate separators, encoded separators, or a filesystem/library-specific traversal quirk) is a candidate bypass — this is a blocklist, and blocklists are inherently incomplete by construction, which is the general lesson from CVE-2023-2825's "N+1 nested groups" bypass of whatever confinement existed before that fix.
- A new route that builds a path from **multiple** concatenated parameters (e.g., a group-nesting chain plus a filename, mirroring the exact CVE-2023-2825 shape) where the traversal check is only applied to one of the parameters, not the assembled result.
- Any Gitaly-bound "relative path" parameter (`gl_repository_path`, `relative_path` in [SYSTEM_CONTEXT.md §7](SYSTEM_CONTEXT.md)) that reaches Gitaly without going through the Rails-side access-check/canonicalization at all, since Gitaly itself does no authorization or path confinement.

**Candidate locations (current source, files that call the traversal-check helpers, confirming the invariant's intended enforcement points — each is worth manually confirming the check is both present *and correctly enforced*):**
- `app/controllers/concerns/uploads_actions.rb:49-50` (`Gitlab::PathTraversal.check_path_traversal!(filename_param)` in `#show`) — the exact subsystem CVE-2023-2825 hit; confirm this specific call site (and its siblings for create/destroy) actually covers every parameter used to build the final disk path, not just `filename_param`.
- `app/services/mcp/tools/repositories/get_repository_file_tool.rb:138` and `app/services/mcp/tools/repositories/blobs_tool.rb` — **newer, Agent-Platform/MCP-exposed** file-read tools using `Gitlab::PathTraversal.path_traversal?`; per [THREAT_MODEL.md T3-D](THREAT_MODEL.md), newer surfaces are statistically where this codebase's recurring patterns next appear, and these are boolean-check call sites specifically — worth confirming the boolean result is actually enforced (raises/aborts) rather than just logged.
- `app/controllers/projects/releases_controller.rb`, `app/controllers/projects/refs_controller.rb`, `app/models/merge_request_diff.rb`, `app/models/concerns/sanitizable.rb`, `app/services/bulk_imports/{file_download_service,file_decompression_service,archive_extraction_service}.rb`, `app/finders/uploader_finder.rb` — the full set of current call sites of the path-traversal helpers found by source search; each is a place where the invariant is *believed* to be enforced and should be checked for the double-decode and unenforced-boolean patterns above.
- Conversely: `app/controllers/projects/tree_controller.rb`, `blame_controller.rb`, `blob_controller.rb` build paths (matched on `File.join`/`Pathname.new` patterns) but did **not** appear in the `check_path_traversal`/`PathTraversal` search — these are the highest-priority candidates to manually confirm actually delegate to Gitaly with a pre-validated ref/path rather than doing any of their own unguarded path construction.

**Required attacker capability:** none (CVE-2023-2825 was fully unauthenticated against a public project) to low (project member, for private-repo variants).

**Potential impact:** Critical — unauthenticated arbitrary file read (source code, credentials, `secrets.yml`-class files), as demonstrated twice at CVSS 10.0.

---

## INV-03 — CI/CD pipeline and job execution always carries the identity/permission set of the legitimately-authorizing user, never a different one, and that identity cannot change between authorization and execution

**Invariant:** (a) A pipeline job's effective permissions are always exactly those of the user who was actually authorized to trigger it; (b) any state a gating/authorization decision was made about (which commit, which user, which approval count) is the same state acted upon at execution time — no TOCTOU window between check and act.

**Why it matters:** Highest CVE density of any class found in this research — **five** distinct CVEs in CI/CD identity/authorization in 2024 alone, plus two TOCTOU-flavored races (2019, 2024) in the same general area (pipeline/approval gating). [SYSTEM_CONTEXT.md §2](SYSTEM_CONTEXT.md) independently flagged the credential model as unusually complex (≥10 parallel credential types resolved by a single `AuthFinders` chain) *before* this historical research confirmed that complexity correlates with the bug history — convergent evidence from two independent methods.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 11](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2024-6385, CVE-2024-5655, CVE-2024-9164, CVE-2024-8641, CVE-2024-11669) and [Class 14.2](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2024-11222, pipeline-creation TOCTOU letting a Developer act in another user's MR-commit context) and [Class 14.1](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2019-11546, MR-approval race).

**Relevant components:** pipeline-creation service objects, `Ci::Runner`/job-token resolution (`lib/gitlab/auth/auth_finders.rb#find_user_from_job_token`, `find_job_from_job_token`), `lib/api/internal/base.rb#check_allowed` (the gitlab-shell/Gitaly access-check path, itself already a "compute check result, then act" shape per [SYSTEM_CONTEXT.md §7](SYSTEM_CONTEXT.md)), job-token-scope enforcement (`lib/api/project_job_token_scope.rb`), the CI job-token-vs-session-token boundary in `Gitlab::Auth::AuthFinders`.

**Potential violation patterns:**
- Job-token scope enforcement (`ci_job_token_scope`/the allowlist feature) implemented as a helper that most, but not literally all, job-token-accepting endpoints call — exactly the shape of CVE-2024-11669 ("overly broad application of token scopes"); any new API file added to `lib/api/*.rb` with `route_setting :authentication, job_token_allowed: true` (or the equivalent) that doesn't also invoke the scope-check helper reproduces this.
- Any code that derives a *different, more powerful* credential (a session token, a broader-scoped PAT) from a narrower one (a job token) without an explicit, intentional exchange/consent step — the CVE-2024-8641 shape.
- A pipeline/job's authorization is computed once (e.g., at trigger/schedule time, checking "can this user trigger a pipeline on this ref") and then a separate code path later determines *whose identity the job carries* (e.g., a scheduled-pipeline owner, a merge-train re-trigger, a retried job) without re-deriving it from the same authorization decision — this is the class of bug GitLab did not publicly disclose the mechanism for (CVE-2024-6385/-5655), so it must be found by direct source reading rather than pattern-matching a known fix.
- Approval-count or "pipeline must succeed" gating checks read current state, then a separate action (merge, job dispatch) proceeds without re-validating that state inside the same transaction/lock — the CVE-2019-11546/CVE-2024-11222 shape.

**Candidate locations (current source, from [SYSTEM_CONTEXT.md §7](SYSTEM_CONTEXT.md) and this pass's `lib/api` scan):**
- The 39 files under `lib/api/*.rb` found to reference `job_token_allowed`/job-token route settings (`lib/api/ci/{runner,pipelines,jobs,job_artifacts,catalog,secure_files}.rb`, `lib/api/{merge_requests,notes,commits,releases,repositories,files,environments,deployments,tags,branches}.rb`, all the `packages`/registry endpoints) — each is a place that accepts job-token auth and must be individually confirmed to apply the job-token-scope check; the *number* of distinct files (39) accepting this credential type is itself the risk signal, since CVE-2024-11669 showed the enforcement was not uniform across a similarly large endpoint set.
- `lib/api/internal/base.rb#check_allowed` (`check_result = access_check_result; return check_result if unsuccessful_response?(check_result); ... payload = {...}`) — a canonical "check, then build a privileged payload" sequence; confirm nothing about `project`/`actor` can be mutated by a concurrent request between the check and the payload construction (same general shape as the CVE-2024-11222 pipeline race, applied to the gitlab-shell/Gitaly access-grant path instead of pipeline creation).
- Sidekiq workers that receive a project/user/pipeline ID as a plain argument and act on it later (flagged generally in [SYSTEM_CONTEXT.md §10](SYSTEM_CONTEXT.md) as "the authorization decision made at enqueue time may be stale by execution time") — any CI-pipeline-related worker in `app/workers/` (not individually enumerated in this pass; a full listing of pipeline/job-related worker classes and whether each re-checks authorization at `#perform` time is the concrete next step).

**Required attacker capability:** low (Developer-level CI trigger ability in most historical instances; CVE-2024-8641 additionally requires the attacker to already have obtained a victim's job token).

**Potential impact:** Critical — private-repository read, secret/variable exfiltration, code/data manipulation via a pipeline run with another (potentially highly privileged) user's effective permissions.

---

## INV-04 — Every code path that resolves and consumes a stored or attacker-influenced URL for an outbound server-side request goes through the same, pinned, DNS-rebinding-resistant HTTP client

**Invariant:** the IP address validated as "safe to connect to" is the exact IP address the connection is made to — no code path re-resolves a hostname after validation, and no code path bypasses the central HTTP client wrapper to make its own request.

**Why it matters:** the highest-*volume* historical class (at least 3 independent researcher reports in 2019 alone), and the exact fix this produced (`dns_rebind_protection`/IP-pinning) is confirmed, by direct source read, to still be the active mitigation — but confirmed to be **inconsistently applied even within the current code**: [SYSTEM_CONTEXT.md §13](SYSTEM_CONTEXT.md) found that `AddressableUrlValidator::BLOCKER_VALIDATE_OPTIONS` explicitly sets `dns_rebind_protection: false` for model-*validation*-time checks (by deliberate design, to avoid breaking saves for not-yet-resolvable hosts), relying entirely on the *request-time* `Gitlab::HTTP` call to re-enforce it.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 1](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2019-5464 (HackerOne #513098 original, #541169 and #632101 independent duplicates) and CVE-2021-22214 (CI Lint/import SSRF).

**Relevant components:** `gems/gitlab-http/lib/gitlab/http_v2/url_blocker.rb` (the current, hardened validator), `app/validators/addressable_url_validator.rb` / `public_url_validator.rb`, `app/services/web_hook_service.rb`, any integration/importer that fetches a user-supplied URL.

**Potential violation patterns:**
- A new feature that fetches a stored URL using a raw `Net::HTTP`, `open-uri`, `RestClient`, or a bespoke `Faraday.new` connection instead of `Gitlab::HTTP` — bypasses the wrapper entirely rather than bypassing the rebind check specifically.
- A background worker or importer that resolves a hostname once (e.g., to log or cache the IP) and a second time to actually connect, reintroducing the exact 2019 TOCTOU even while nominally "using" the validator.
- Direct-upload / remote-mirror / dependency-proxy features that hand a URL to an underlying gem (fog/aws-sdk, an npm/PyPI proxy client) whose own HTTP layer does its own DNS resolution outside `Gitlab::HTTP`'s control.

**Candidate locations (current source):** a full enumeration of every non-`Gitlab::HTTP` HTTP client call site was not completed in this pass (time-boxed); this pass's grep confirmed `lib/gitlab/prometheus_client.rb` and `lib/gitlab/faraday/error_callback.rb` use Faraday directly rather than `Gitlab::HTTP`, and `lib/gitlab/http_io.rb` uses `Net::HTTP` directly (for range-request object-storage streaming) — **each of these three is a candidate for confirming whether the URL it connects to can ever be attacker-influenced** (Prometheus integration URL is admin-configured, lower risk; `http_io.rb`'s URL source needs tracing). The full set of `app/models/integrations/*` classes (Slack, PagerDuty, generic webhook-based integrations, per [SYSTEM_CONTEXT.md §5](SYSTEM_CONTEXT.md)) is the highest-value area to check systematically for the same reason — each is architecturally a mini-plugin with its own outbound-request code, and this pass did not have time to individually audit all of them.

**Required attacker capability:** ability to create/edit a webhook, integration, or import-by-URL target (Maintainer-level project access in most historical instances; CVE-2021-22214's CI-Lint variant was unauthenticated).

**Potential impact:** Critical — internal-network/cloud-metadata SSRF with response read-back, historically discussed by GitLab's own security team as a potential path to full compromise depending on cloud environment.

---

## INV-05 — Every state-changing / equivalent-privilege-reachable entry point enforces identical CSRF protection, regardless of which of GitLab's several parallel API surfaces (classic REST, single GraphQL query, batched/multiplex GraphQL) is used to reach it

**Invariant:** the decision "does this request need a valid CSRF token" must produce the same answer for functionally equivalent operations regardless of transport/batching shape.

**Why it matters:** Confirmed to recur specifically at the REST/GraphQL boundary (2026) after a 2017 instance in a different mechanism (token leak via protocol-relative redirect) — this is a smaller-volume class than INV-01/02/03 but sits exactly on the "one of several equivalent entry points to the same functionality didn't get the security control" pattern that this document's other invariants also show repeatedly (INV-03's job-token-scope gap, INV-06's authorization-drift).

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 4](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2026-19650 (CSRF in the GraphQL multiplex/batched-query handler, CVSS 7.1) and the separately-disclosed HackerOne #1122408 ("CSRF on /api/graphql").

**Direct source verification performed this pass:** read the **current** `app/controllers/graphql_controller.rb` in full. The present-day logic is:
```ruby
skip_before_action :verify_authenticity_token, if: -> {
  current_user.nil? || sessionless_user? || !any_mutating_query?
}
```
where `any_mutating_query?` for a multiplex request iterates **every** query in the batch (`multiplex_param.any? { |q| mutation?(q[:query], q[:operationName]) }`) and `mutation?` fails *closed* (treats a `GraphQL::ParseError` as `true`, i.e. as mutating, forcing CSRF enforcement) — this appears to be the actual fix for CVE-2026-19650, applied comprehensively to the batched case, not just the single-query case. This is a positive finding, not a live gap, but it is a **hand-rolled, GraphQL-string-parsing re-implementation** of "is this operation sensitive," which is exactly the kind of control that has drifted out of sync with its equivalents before.

**Relevant components:** `app/controllers/graphql_controller.rb#mutation?`/`#any_mutating_query?`, `app/controllers/application_controller.rb` (the REST/HTML baseline CSRF behavior), any newer query mechanism (persisted queries, a subscription-establishment handshake) that might not route through `#any_mutating_query?` at all.

**Potential violation patterns:**
- A new GraphQL entry mechanism (persisted/pre-registered queries referenced by ID rather than raw query text, or a subscription `@stream`/`@live` directive with a side effect) that bypasses the `GraphQL.parse`-based `mutation?` check because it never contains the literal query text `mutation?` inspects.
- A mutation reachable through a field-level side effect that isn't of GraphQL `operation_type == "mutation"` (e.g., a `Query`-typed field whose resolver has a write side effect — an anti-pattern, but the sort of thing that would silently defeat this specific detection method since it only checks operation type, not resolver behavior).
- Any controller that independently reimplements its own `skip_before_action :verify_authenticity_token` condition (this pass found 12 such controllers — see list below) — each is a separate hand-written CSRF-applicability decision, and any one of them getting the condition wrong is architecturally identical to the GraphQL multiplex gap.

**Candidate locations (current source — every controller found in this pass that independently disables/conditions CSRF protection, i.e. every place this invariant is separately re-implemented rather than inherited once from a single control point):**
`app/controllers/sent_notifications_controller.rb`, `app/controllers/groups/dependency_proxy_for_containers_controller.rb`, `app/controllers/graphql_controller.rb`, `app/controllers/oauth/dynamic_registrations_controller.rb`, `app/controllers/mailgun/webhooks_controller.rb`, `app/controllers/jwt_controller.rb`, `app/controllers/repositories/git_http_client_controller.rb`, `app/controllers/concerns/workhorse_authorization.rb`, `app/controllers/jira_connect/application_controller.rb`, `app/controllers/concerns/snippets_actions.rb`, `app/controllers/projects/alerting/notifications_controller.rb`, `app/controllers/projects/incident_management/pager_duty_incidents_controller.rb`. Most of these are legitimately CSRF-exempt (webhook receivers, git-over-HTTP, token-authenticated endpoints) — the useful next step is confirming each one's exemption condition is as tightly scoped as GraphQL's now is (fails closed, checks the actual authentication mode) rather than a blanket `skip_before_action` with no condition.

**Required attacker capability:** ability to get an authenticated victim to load an attacker page (standard CSRF precondition); no special privilege.

**Potential impact:** High — arbitrary GraphQL mutation/query execution as the victim; severity depends entirely on which mutation is reachable (could range from low-impact settings changes to destructive actions).

---

## INV-06 — Every code path that returns or acts on an object re-applies that object's containing project/group visibility and confidentiality rules — an ID/IID-keyed lookup can never be a side door around the same check the default listing view enforces

**Invariant:** authorization is a property of *every* access path to an object, not of the "normal"/expected UI path to it.

**Why it matters:** [SYSTEM_CONTEXT.md §3, Flow C](SYSTEM_CONTEXT.md) independently predicted this exact bug shape from reading the DeclarativePolicy/GraphQL authorization architecture (REST and GraphQL maintain **independent** authorization declarations over the same models) before this historical research confirmed **four** separate CVEs with precisely this mechanism, spanning 2022 to 2026 — i.e. it is still actively recurring, not a closed historical chapter.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 12](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2022-1352 (issue title disclosure via ID-keyed API lookup bypassing "members only" visibility), CVE-2022-1545 (confidential-notes disclosure), CVE-2026-1080 (iterations API reaching private descendant-group data), CVE-2025-14594 (pipeline-data IDOR, explicitly CWE-639 "Authorization Bypass Through User-Controlled Key").

**Relevant components:** `app/finders/*` (the intended single source of truth for "what can this user see," per [SYSTEM_CONTEXT.md §3](SYSTEM_CONTEXT.md)), `app/graphql/resolvers/*`, `app/graphql/types/*` (`authorize` declarations), REST endpoints in `lib/api/*.rb` that accept an `id`/`iid` parameter.

**Potential violation patterns:**
- A GraphQL resolver calls a model's `.find`/`.find_by` directly (or a batch-loader keyed only by ID) instead of routing through the equivalent project/group-scoped Finder — bypasses whatever visibility filtering is baked into the Finder but not re-implemented in the resolver.
- A REST endpoint's `authorize!`/policy check is written against the *parent* object (e.g., "can read project X") without an additional, more specific check for the *child* object's own visibility flag (confidential issue, restricted iteration, private descendant group) — exactly the CVE-2026-1080 shape ("private descendant groups" implies the check was performed at the wrong level of the namespace hierarchy).
- Two API surfaces (REST vs GraphQL) exposing the same underlying model with different authorization completeness, discoverable by comparing what each returns for the same object ID.
- A newer feature (iterations, work items, Organizations) copies an older endpoint's authorization pattern by reference/similarity rather than by shared code, so a fix to the older path never propagates.

**Candidate locations:** a full source-level enumeration of every GraphQL resolver's `.find`-vs-Finder usage was attempted this pass (`app/graphql/resolvers/`) but returned no direct matches for the specific patterns searched (`Issue.find(`, `Note.find(`, `MergeRequest.find(`) — this is a **negative result that should not be read as "clean"**: it most likely means the actual lookups are batch-loaded or use different method names (`.find_by_iid`, GlobalID-based lookups via `GitlabSchema.object_from_id`, or Finder classes called with insufficiently narrow scope) that a broader, dedicated pass would need to enumerate; the highest-value next step is auditing `GitlabSchema.object_from_id`/`Types::GlobalIDType` resolution (how a client-supplied GlobalID becomes a loaded object) and confirming every type's `authorize` declaration is checked *after* that resolution and *before* any field on the object is exposed, plus specifically re-examining the **Iterations** and **work items** GraphQL types/resolvers given they are the two most recent confirmed-vulnerable areas (CVE-2026-1080, and work items being the newest major GraphQL surface per the `EXTENDED_QUERY_SIZE_ALLOWLIST` migration comment seen live in `graphql_controller.rb` during this pass, indicating active, recent development there).

**Required attacker capability:** low — typically just being an authenticated user with knowledge or guessability of a target ID/IID; CVE-2022-1352's variant may not even have required authentication.

**Potential impact:** Medium historically (title/metadata disclosure), but High where the exposed object is itself sensitive (confidential notes, private-group data, credentials/CI variables embedded in the object) — the ceiling for this class is set by *what* object type is reachable, not the bypass mechanism itself.

---

## INV-07 — A native/C-extension parser invoked on attacker-supplied bytes performs its own bounds checking; GitLab never assumes a dependency's parser is memory-safe merely because the surrounding code is Ruby

**Invariant:** every size/length/nesting-depth field read from untrusted input and used to index or size a buffer inside a native extension is validated against the buffer's actual allocated size before use.

**Why it matters:** proven, in 2026, to be a viable full-RCE chain (not just theoretical) from an ordinary, low-privilege action (pushing a repository file) — and the researcher explicitly noted GitLab's general-purpose JSON gem (Oj) has **8 sibling CVEs** beyond the one exploited, meaning the *dependency*, not just the one feature, is the risk unit.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 7](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2026-54902 chain (Oj stack out-of-bounds write + heap-pointer disclosure, reached via `ipynbdiff`'s `Oj::Parser.usual.parse` on pushed `.ipynb` files), plus the explicit governance note that this fix was **not filed as a security advisory**, only as a dependency-version "bug fix," which the reporting outlet flagged as a triage gap in its own right.

**Relevant components:** any gem wrapping a native C/C++/Rust extension that parses attacker-reachable content: Oj (general JSON), Nokogiri (XML/HTML, also load-bearing for the SAML class, INV-08), `rexml`, image-processing libraries, `ipynbdiff` specifically.

**Potential violation patterns:**
- Any new "render a diff/preview of an uploaded or committed file type" feature (the exact shape of the vulnerable feature) that hands raw repository bytes to a native parser without a size/complexity cap first.
- Continuing to depend on an outdated pinned version of a native-extension gem after a memory-safety fix has shipped upstream, especially where (per this class's own evidence) the fix might ship unlabeled as a security fix and therefore not trigger the same patch-prioritization urgency.

**Candidate locations:** this pass's search for other `Oj::Parser`/`Oj.load`/`Oj.dump` call sites in `app/` and `lib/` (beyond the `ipynbdiff` gem itself, which is vendored separately and was not in this sparse checkout) returned `lib/gitlab/json/safe_parser.rb`, `lib/gitlab/fp/settings/env_var_override_processor.rb`, and `lib/api/helpers/commits_body_uploader_helper.rb` — each is worth checking for (a) whether it calls Oj on attacker-reachable content the way `ipynbdiff` did, and (b) whether `lib/gitlab/json/safe_parser.rb` specifically is the safe wrapper every other JSON-parsing call site in the app should be routed through (its name suggests it may already be the intended single-enforcement-point, which would make any call site that uses raw `Oj`/`JSON` instead of this wrapper a policy violation independent of any specific memory bug). A full audit of the current `Gemfile.lock` pin for `oj` against the fixed version (3.17.3+) on the actual test instance is the fastest, highest-confidence check in this entire document.

**Required attacker capability:** low — ordinary push access to a project (no special role), per the historical PoC.

**Potential impact:** Critical — full RCE as the application's OS-level worker user, per the historical chain.

---

## INV-08 — The XML/document node whose cryptographic signature is verified is the exact same node whose content is later trusted, resolved via a single, consistent parser identity throughout

**Invariant:** signature verification and content consumption must operate on an identical, unambiguous parse tree — never two independently-parsed views of "the same" document.

**Why it matters:** produced a full, unauthenticated, "log in as anyone including admins" bypass (CVSS 10.0) in 2024, directly on GitLab's SSO login path, and [SYSTEM_CONTEXT.md §2](SYSTEM_CONTEXT.md) confirmed by direct `Gemfile` read that the exact same dependency pair (`ruby-saml`, `rexml`) that produced this bug is still what the current instance depends on for SAML.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 8](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2024-45409 (REXML used for `SignedInfo`/`SignatureValue` extraction, Nokogiri used for the assertion/`DigestValue` content, with non-relative XPath queries permitting extra, attacker-inserted elements to satisfy each parser's view independently — XML Signature Wrapping), with a noted follow-on `ruby-saml` CVE (CVE-2025-25292) in GitLab's own advisory database.

**Relevant components:** `omniauth-saml`/`ruby-saml` (vendored dependency, consumed by `app/controllers/omniauth_callbacks_controller.rb` per [SYSTEM_CONTEXT.md §2](SYSTEM_CONTEXT.md)), any other place GitLab independently verifies a signed document/token (JWT verification paths — Workhorse JWTs, Kubernetes-agent JWTs, DPoP tokens per [SYSTEM_CONTEXT.md §2 item 9](SYSTEM_CONTEXT.md) — are a *conceptually* related but mechanically different trust-decision class worth the same "is verification-target and consumption-target guaranteed identical" question, even though JWTs don't have ruby-saml's specific two-XML-parser problem).

**Potential violation patterns:**
- This specific bug requires no new code to reproduce — it is purely a **dependency-currency** question: is the installed `ruby-saml`/`omniauth-saml`/`rexml` version at or above the fixed release?
- More generally: any future GitLab-authored code that adds its own XML/XPath-based extraction *alongside* a gem's own parsing (e.g., a custom SAML attribute-mapping feature that re-parses the assertion XML independently of what `ruby-saml` already validated) reintroduces the same two-parser-views-of-one-document risk in first-party code.

**Candidate locations:** `Gemfile` line pins for `ruby-saml ~> 1.18` and `rexml ~> 3.4.0` (confirmed present in the current source by direct read for [SYSTEM_CONTEXT.md](SYSTEM_CONTEXT.md)) — the concrete, fast action is comparing these pins against the fixed-version list in [Class 8](HISTORICAL_VULNERABILITY_MODEL.md) and the referenced CVE-2025-25292 advisory on the actual test instance's `Gemfile.lock`, not the abstract `Gemfile` range (a `~>` pin can still resolve to a vulnerable patch version depending on when `bundle install` was last run).

**Required attacker capability:** none beyond network access to the SSO login endpoint, plus possession of any one validly-signed SAML document from the same IdP (their own login response suffices) — only relevant on instances with SAML SSO configured (true of the planned GDK test instance if SAML is enabled for testing).

**Potential impact:** Critical — full unauthenticated authentication bypass as an arbitrary user, including admins.

---

## INV-09 — Data received from an external/imported source is data, never command syntax, code, or an evaluation target

**Invariant:** content originating from an import source (a "GitHub" server GitLab imports from, an uploaded archive, imported repository metadata) is only ever used as inert data — string interpolation into a shell command, `eval`, or an unsandboxed native parser's evaluation-capable code path is never reachable from it.

**Why it matters:** produced one Critical (CVSS 9.9) authenticated RCE via OS command injection (2022) and, in the same general "external/imported content reaches a dangerous interpretation step" family, the unauthenticated ExifTool RCE (2021, CVSS 10.0, actively exploited/KEV-listed) — two of this document's highest-severity historical bugs share this root shape even though their specific mechanisms (shell injection vs. embedded-eval-in-a-parser) differ.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 5](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2022-2884, GitHub-import RCE) and [Class 6](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2021-22205, ExifTool DjVu RCE via content-based file-type sniffing overriding the intended upload-type restriction).

**Relevant components:** `lib/gitlab/import_export/*` (project/group import-export), any GitHub/Bitbucket/Gitea/FogBugz importer service, `lib/gitlab/import_export/command_line_util.rb` (archive/tar handling), file-upload metadata-extraction pipelines.

**Potential violation patterns:**
- Any remaining shell-out (`system`, backticks, `%x{}`, `Open3.capture*`, `IO.popen`) in an importer or archive-handling path where any argument is built from imported/attacker-influenced data without strict allowlisting or proper argument-array (non-shell) invocation.
- A file-upload or attachment-processing pipeline that determines *how* to parse a file by sniffing its content (as ExifTool did) rather than strictly by the type the upload feature intended, allowing a more dangerous parser than intended to be invoked by mislabeling a file.

**Candidate locations:** this pass's search of `lib/gitlab/import_export/command_line_util.rb` (the general archive/tar-handling utility for project import-export) found **no** direct shell-out pattern (`system(`/backticks/`Open3`/`IO.popen`) in that specific file — a genuinely negative result, suggesting the general import-export archive path may already avoid raw shelling out (likely using Ruby's `Gem::Package::TarReader`/library-level tar handling instead). This means the CVE-2022-2884 mechanism most likely lived in the **GitHub-specific** importer code (not included in this sparse checkout — `app/services/gitlab_projects_import` / `Gitlab::GithubImport::*`-style paths would need to be pulled and reviewed specifically) rather than the general import-export framework; that GitHub/Bitbucket/Gitea importer code is the concrete next-step candidate location, not the already-checked `command_line_util.rb`. For Class 6 (file-type-sniffing RCE): the current upload pipeline's metadata-extraction step (whatever superseded the vulnerable ExifTool invocation) was not located in this sparse checkout and should be pulled and reviewed to confirm file-type determination is now strictly extension/declared-type-based (or fully sandboxed) rather than content-sniffed.

**Required attacker capability:** authenticated user with project-creation/import permission (CVE-2022-2884) or, for the file-parser class, an unauthenticated/low-privilege upload capability (CVE-2021-22205).

**Potential impact:** Critical — full RCE as the application's OS user in both historical instances.

---

## INV-10 — An account provisioned via an external identity provider has no usable, guessable local password; credential-recovery flows deliver their token only to a previously-verified destination, immune to multi-value parameter pollution

**Invariant:** two related sub-invariants, grouped because both are narrow, one-off authn-logic failures rather than deeply recurring architectural patterns: (a) SSO-provisioned accounts cannot be logged into via the local password form using any predictable value; (b) a password-reset (or equivalent recovery) token is only ever delivered to an address/destination whose ownership was verified *before* the reset was requested, and the parameter carrying that destination cannot be silently overridden by supplying multiple values.

**Why it matters:** each produced a Critical (CVSS 9.1 and 10.0 respectively), zero-to-low-effort, full account-takeover bug — among the highest-severity, lowest-attacker-effort bugs in the entire historical record.

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 9](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2022-1162, hardcoded OmniAuth password) and [Class 10](HISTORICAL_VULNERABILITY_MODEL.md) (CVE-2023-7028, password-reset parameter pollution via a secondary-email feature added in 16.1.0).

**Relevant components:** Devise `recoverable` (`app/controllers/passwords_controller.rb`), OmniAuth account-provisioning code, any endpoint that accepts an email/destination parameter for a security-sensitive delivery (invite emails, notification-preference changes, 2FA-recovery-code delivery).

**Potential violation patterns:**
- Any endpoint reading a security-sensitive destination parameter with `params[:x]` rather than Devise/Rails strong-parameter single-value semantics, allowing an array (`x[]=a&x[]=b`) to silently pick an unintended value.
- Any future "add a secondary/alternate identity" feature (the same shape as the 16.1.0 secondary-email feature that caused CVE-2023-7028) that reuses an existing security-sensitive flow without re-auditing that flow's parameter handling.

**Candidate locations:** `app/controllers/passwords_controller.rb` and the underlying Devise `recoverable` parameter handling — confirm the email parameter is read as a single strong-permitted value (`params.require(:user).permit(:email)`-style) rather than anything that could accept an array, and confirm the current multi-email/secondary-email account-recovery logic (if the feature still exists in its 16.1.0 form) verifies ownership of a destination *before*, not after, using it as a delivery target. This was not independently re-verified against current source in this pass (time-boxed) and is a concrete, fast next step given the severity.

**Required attacker capability:** none for CVE-2023-7028 on a non-SSO-enforced instance (fully unauthenticated, zero-click); none for CVE-2022-1162 beyond a known/guessed target username.

**Potential impact:** Critical — full, unauthenticated account takeover.

---

## INV-11 — GitLab's own outbound-facing reverse proxy (Workhorse) and the Rails backend agree, for every request, on where that request's boundaries are and which handler/backend it is destined for

**Invariant:** no request can be classified one way by Workhorse's route matcher and a different way by the eventual handler — request framing (headers, `Content-Length`/`Transfer-Encoding`, path matching) must be unambiguous end-to-end.

**Why it matters:** produced 3 CVEs in a single 2020 release (disclosure of job artifacts, package files, and arbitrary `/tmp` content), and [SYSTEM_CONTEXT.md §1](SYSTEM_CONTEXT.md) confirms the architecture that caused it — a large table of regex-pattern + matcher-function route entries in `workhorse/internal/upstream/routes.go` deciding backend and handling per request — is structurally unchanged today, just larger (this pass's read of the current `routes.go` counted well over 150 distinct route entries, up from whatever smaller set existed in 2020).

**Historical evidence:** [HISTORICAL_VULNERABILITY_MODEL.md Class 13](HISTORICAL_VULNERABILITY_MODEL.md) — CVE-2020-6833, CVE-2020-11505, CVE-2020-11506.

**Relevant components:** `workhorse/internal/upstream/routes.go`, the per-route `matchers`/`withMatcher` mechanism, body-limit and content-type matchers (`withBodyLimit`, `isContentType`) seen directly in this pass's earlier source read.

**Potential violation patterns:**
- A newly-added route (this codebase adds routes frequently — this pass observed AI/Duo-workflow, observability, and MCP-adjacent routes as recent additions) whose regex is broader or whose matcher function is weaker/absent compared to structurally similar neighboring routes, such that a request crafted to satisfy the loose route's pattern is actually processed by a different, more sensitive handler than the route table's author intended.
- Any route lacking an explicit `withBodyLimit`/`withBodyLimitMode` where a structurally similar route (e.g., another upload-accepting route) has one — an inconsistency of this kind was exactly what let smuggled/oversized requests reach unintended handling in the 2020 CVEs' general class (request-framing confusion).

**Candidate locations:** the newest entries in `workhorse/internal/upstream/routes.go` (by definition the least field-tested) — this pass's earlier read for [SYSTEM_CONTEXT.md](SYSTEM_CONTEXT.md) specifically noted the AI/Duo-workflow routes (`v4/ai/duo_workflows/ws`, `v4/ai/duo_workflows/workflows/\d+/execute`) and observability routes (`observability/v1/{traces,logs,metrics,analytics,services}`) as recent, comparatively less-hardened additions worth comparing matcher-by-matcher against older, more battle-tested routes of the same general shape (e.g., the long-standing `git_upload_pack`/`git_receive_pack` routes, which carry `isContentType` matchers the newer routes may or may not replicate).

**Required attacker capability:** network access to the instance; historical severity (CVSS 7.5) implies no authentication required.

**Potential impact:** High — disclosure of job-artifact uploads, package files, and arbitrary files under `/tmp`.

---

## Priority ranking (restated, with justification)

1. **INV-02 (path traversal)** — 2 Critical/CVSS-10.0 unauthenticated instances 3 years apart, the most recent one (CVE-2026-85706) still exploited in the wild as of the most recent evidence available, plus this pass's direct finding that the current central defense (`Gitlab::PathTraversal`) is architecturally a *weaker* pattern (regex blocklist) than the one used for uploads (canonicalize+allowlist) — highest combination of recurrence, currency, and severity.
2. **INV-03 (CI/CD identity/TOCTOU)** — highest raw CVE count (7 across two related invariants) concentrated in 2024, directly overlapping a credential-model complexity independently flagged from architecture alone.
3. **INV-01 (redirect/URL construction)** — longest recurrence span (2017–2024, 5 instances), with GitLab's own engineering team on record admitting a fix was incomplete, showing the pattern actively defeats point-fixes.
4. **INV-06 (IDOR/BOLA)** — actively recurring through 2026 (not a closed historical chapter), independently predicted by architecture review before the CVE evidence was gathered.
5. **INV-04 (SSRF/DNS rebinding)** — high historical volume but the specific 2019 mechanism is confirmed fixed and durable; residual risk is narrower (new code paths bypassing the wrapper) rather than a live gap in the wrapper itself.
6. **INV-07 (native-extension memory corruption)** — most severe single historical outcome (full RCE) and most recent (2026), but requires the most specialized exploitation skill and the specific instance is already fixed; residual risk is dependency-currency and sibling call sites.
7. **INV-05 (CSRF across API surfaces)** — real and recent (2026) but the specific instance's fix, read directly from current source, appears comprehensive; residual risk is structural (12 independently-implemented CSRF exemptions) rather than a known-open gap.
8. **INV-08 (SAML parser differential)** — Critical impact but conditional on SAML being enabled, and the concrete check is fast/conclusive (a version-pin comparison) rather than open-ended research.
9. **INV-09 (command injection / unsafe file-type parsing)** — Critical historical impact, but this pass's own source check found the general import-export path already avoids the obvious shell-out pattern; the historically-vulnerable GitHub-importer-specific code wasn't available in this checkout to re-examine.
10. **INV-10 (hardcoded credential / recovery parameter pollution)** — extremely severe when present but narrow, non-recurring, one-off logic bugs rather than an architectural pattern likely to have further undiscovered siblings.
11. **INV-11 (Workhorse request smuggling)** — architecturally still possible, but no recurrence in 6 years suggests the original bypass techniques were durably closed; would require protocol-level expertise, not source review, to find a new instance.

No testing has been performed against any instance. This document is a source-analysis and prioritization artifact; the next step (not yet started) is standing up a local GDK/Docker instance and tracing INV-02 or INV-03 end-to-end, per [THREAT_MODEL.md](THREAT_MODEL.md)'s net recommendation, refined here by this pass's additional source-level findings (in particular, INV-02's confirmed blocklist-vs-allowlist architectural gap). Waiting for instruction before any live testing begins.
