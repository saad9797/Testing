# AUDIT_COVERAGE.md

Honest accounting of what this engagement has and has not covered, per the requested end-of-engagement structure. No live testing has occurred at any point in this engagement — everything below is source-level research against the public `gitlab-org/gitlab` repository, consistent with [TARGET_SELECTION.md](TARGET_SELECTION.md)'s scope authority (my own instance only; no such instance exists in this environment).

**Applications tested:** none, live. Zero HTTP requests have been sent to `gitlab.com` or any GitLab-operated asset in this entire engagement.

**Eligible assets tested:** none, live — see [SCOPE_MATRIX.md](SCOPE_MATRIX.md).

**Endpoints discovered (via source, not live crawling):** ~180 REST API resource files (`lib/api/*.rb`), the full GraphQL schema surface (`app/graphql/{types,resolvers,mutations}/`), and the Workhorse route table (`workhorse/internal/upstream/routes.go`, ~150+ entries) — enumerated and characterized in [SYSTEM_CONTEXT.md](SYSTEM_CONTEXT.md); no ENDPOINT_INVENTORY.md/JS_INVENTORY.md were produced because those artifacts specifically describe a live-web-app JS-crawling methodology that does not apply to a self-hosted product with no running instance to crawl.

**Historical vulnerabilities reviewed:** 24, across 14 recurring classes ([HISTORICAL_VULNERABILITY_MODEL.md](HISTORICAL_VULNERABILITY_MODEL.md)), 5 with full patch-diff archaeology ([PATCH_ARCHAEOLOGY.md](PATCH_ARCHAEOLOGY.md)), consolidated into [PATCH_BYPASS_MATRIX.md](PATCH_BYPASS_MATRIX.md) this session with one new sibling-hunt result.

**Security invariants tested:** 11 named invariants ([SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md)), plus the living three-list tracker now maintained in [THREAT_MODEL.md](THREAT_MODEL.md)'s closing section (4 confirmed, 4 suspected/open, 3 disproven as of this session).

**Attack-surface slices completed:** 1 of 20 candidate slices (File upload/download, [ATTACK_SURFACE_SLICES.md](ATTACK_SURFACE_SLICES.md) rank #1) has received full two-pass adversarial review ([SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md), [SLICE_01_DEEP_FINDINGS.md](SLICE_01_DEEP_FINDINGS.md)) plus extracted-logic validation ([VALIDATION_01.md](VALIDATION_01.md)). The Authorization slice (rank #2) has received one independent audit pass ([AUTHZ_AUDIT.md](AUTHZ_AUDIT.md)) plus this session's second-order continuation (move/transfer mutations). The OAuth/OIDC slice (rank #3) and the remaining 17 slices have not been separately audited.

**Hypotheses tested:** at minimum 12 concrete, named hypotheses across this session and prior ones (enumerated in [THREAT_MODEL.md](THREAT_MODEL.md)'s three-list tracker and in [VALIDATION_01.md](VALIDATION_01.md)'s per-candidate classifications).

**Hypotheses disproven:** 6 — the double-slash-route hypothesis is *not* one of these (still open); disproven ones are the runner-resolver gap, the bulk-move coarse-check gap, and the general "move mutations forget the destination" hypothesis (tested against 4 mutations), plus 3 from the file-upload slice's second pass (import-restore identifier traversal, secret-parameter traversal, HTTP-method bypass — see [SLICE_01_DEEP_FINDINGS.md](SLICE_01_DEEP_FINDINGS.md) and [SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md)'s "no finding" sections).

**Confirmed findings (bounty-submittable, i.e. CONFIRMED + reproduced against a live instance):** **zero.** Every candidate produced by this engagement remains at UNCONFIRMED or "audited-and-not-broken," because reproducing any of them against a real instance requires infrastructure (a running GDK/Docker GitLab, or gitlab.com itself, which is out of this engagement's self-imposed scope) that has not been available at any point in this session. This is stated plainly rather than inflated — no finding in this entire research chain should be submitted to HackerOne as-is; every one of them needs live confirmation first.

**Duplicates:** none identified as such, since nothing has been submitted.

**Out-of-scope findings:** none produced — every candidate discussed maps to "my own instance," per [SCOPE_MATRIX.md](SCOPE_MATRIX.md).

**Remaining blocked areas:** anything requiring a live instance (all of Section 9's auth/session audit beyond source reading, Section 11's SSRF live confirmation, Section 15's race-condition reproduction, Section 13's webhook signature verification testing) is blocked on the same missing piece — a running GitLab instance, which this environment cannot currently provide (no Ruby, no Docker; confirmed and a user decision was made earlier this engagement to proceed with source-level work instead of installing a toolchain).

**Remaining unexplored surfaces, in priority order for a future session:**
1. **GraphQL mutations beyond the 4 move/transfer ones checked** — the single highest-value gap this session identified; write mutations in general (not just move/transfer) haven't been systematically audited the way read-resolvers were in [AUTHZ_AUDIT.md](AUTHZ_AUDIT.md).
2. **The two named-but-unconfirmed sibling routes from PATCH_BYPASS_MATRIX.md's CVE-2022-2250 row** (`config/routes/project.rb`'s `commit/:id`/`tree/*id`, `config/routes/repository_deprecated.rb`'s `logs_tree/*path`) — a fast, concrete, still-open lead named by GitLab's own engineers.
3. Standing up an actual GDK/Docker instance to convert any of this engagement's UNCONFIRMED candidates to CONFIRMED or FALSE POSITIVE — nothing in this chain can advance further without it.
4. The 19 attack-surface slices beyond File-upload/download and Authorization that have received no dedicated audit pass at all.
5. Sections 9–16 of the requested playbook (auth/session, parser boundary, SSRF, file/path, webhook, business-logic state-machine, race conditions, admin/debug) — touched only glancingly via the Authorization pass; each deserves its own dedicated pass the way File-upload/download received one.

**Live validation attempt log:** one live-validation step was explicitly attempted (the `logs_tree/*path` single-request test against the CVE-2022-2250 sibling-B finding). Preconditions were checked first: `docker --version` and `ruby -v` both returned "not found," local ports 3000/8080 refused/timed out — no instance exists in this environment. The request was **not sent**; classification recorded at the time was `NOT TESTABLE`.

**Resolved anyway, without an instance, in a later session:** the actual blocking fact was `check_path_traversal_middleware`'s default state, and that's recorded in the source tree itself (`config/feature_flags/ops/check_path_traversal_middleware.yml` → `default_enabled: true` since 16.5) — no live request was needed. Same technique closed the `ruby-saml`/`rexml`/`oj` version-pin questions via `Gemfile.lock`, also part of the source tree at this commit. **Net effect: of this engagement's original three "requires live validation" items, two are now resolved from source alone; only the `remote_id`/`PendingDirectUpload`-ownership question in the file-upload slice genuinely still needs a running instance** (its answer depends on database/ActiveRecord query semantics, not a static config value).

No live testing has been performed. No findings in this chain are ready for submission. Waiting for instruction on which of the above to pursue next.
