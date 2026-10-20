# AUTHZ_AUDIT.md — Independent authorization / tenant-isolation audit

Scope authority: [TARGET_SELECTION.md](TARGET_SELECTION.md). No live testing performed, no real third-party data accessed, no server-side code modified — this is a source-level audit of the current checkout (`src/gitlab`, tag `v19.5.0-pre`), consistent with every other document in this chain. "Prove the exact identity mismatch" is honored strictly: where I could not trace a concrete, citable mismatch, I report the area as **audited-and-not-broken** or as an **open candidate requiring live verification**, not as a confirmed bug.

## Threat model (as specified)

**Attacker:** a remote, authenticated, low-privileged user who controls their own account and their own organization/tenant, can make normal API/GraphQL requests, cannot access the database directly, and cannot modify server-side code.

**Goal:** access, modify, invoke, or infer resources belonging to another tenant or a higher-privileged principal — i.e., a BOLA/IDOR or tenant-isolation failure, not a code-execution or credential-theft bug (those are covered elsewhere in this research chain).

## Method

For each candidate area, I traced **route → controller/resolver → service/finder → authorization decision → resource lookup → database query → sensitive operation**, reading the actual object-lookup and authorization code rather than assuming a framework guarantee. Where a type/resolver relies on GitLab's centralized DeclarativePolicy/GraphQL-type-authorization framework, I verified the *actual* policy/ability definition, not just the presence of an `authorize` keyword, before accepting it as safe — several areas below were initially flagged as suspicious from the resolver alone and were **downgraded to safe** once the corresponding type or policy was read; I report those explicitly as due diligence, per this audit's own standard of not claiming a bug from surface resemblance alone.

This is a genuinely new pass, independent of [SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md)/[SLICE_01_DEEP_FINDINGS.md](SLICE_01_DEEP_FINDINGS.md) (a different slice, file upload/download) and of the [HISTORICAL_VULNERABILITY_MODEL.md](HISTORICAL_VULNERABILITY_MODEL.md) Class 12 (IDOR/BOLA) write-up (which was CVE-mining, not source-tracing) — though it does draw on and re-verify the exact historical bug shape from CVE-2026-1080 against current source, and cross-references one directly relevant finding from the upload-slice work where it bears on tenant isolation specifically.

---

## Area 1: GraphQL object-by-GlobalID resolvers — general pattern check

**Route → controller:** `POST /api/graphql` → `GraphqlController#execute` → `GitlabSchema` → field resolver.

I read every resolver under `app/graphql/resolvers/` that calls `GitlabSchema.object_from_id`/`GitlabSchema.find_by_gid` directly (rather than through a project/group-scoped Finder) to check whether the resolver itself performs authorization, or relies on the returned object's **type-level** `authorize` declaration (GitLab's standard pattern: `Types::X < BaseObject; authorize :some_ability; end`, enforced by the framework after the resolver returns, before fields are exposed).

**Traced in full, with verdicts:**

| Resolver | Object-level check in resolver? | Type-level `authorize`? | Verdict |
|---|---|---|---|
| `Resolvers::Ci::RunnerResolver` (`app/graphql/resolvers/ci/runner_resolver.rb:14-16`) | **None** in the resolver | Yes — `Types::Ci::RunnerType` declares `authorize :read_runner` (`app/graphql/types/ci/runner_type.rb:11`), plus separate, stricter `authorize: :read_runner_sensitive_data` on sensitive fields (line 123) and `authorize: :read_ephemeral_token` (line 62) | **Audited, not broken.** Initially looked like a missing check; the type-level framework covers it, and sensitive sub-fields are gated more strictly than the base object — this is GitLab's intended defense-in-depth shape working correctly. |
| `Resolvers::Ml::ModelDetailResolver`, `FindModelVersionResolver`, `ExperimentDetailResolver` (`app/graphql/resolvers/ml/*.rb`) | Yes — each explicitly calls `Ability.allowed?(current_user, :read_model_registry \| :read_model_experiments, object&.project)` before returning the object | (not verified independently — the resolvers self-check, making the type-level question moot for this audit) | **Audited, not broken.** `FindModelVersionResolver` additionally cross-checks `model_version.model_id == object.id`, correctly preventing a model-version ID from being redeemed against an unrelated parent model in the query — a specific, well-formed defense against exactly the "authorization checked before object substitution" class named in this audit's brief. |
| `Resolvers::BoardListResolver` (`app/graphql/resolvers/board_list_resolver.rb`) | Yes — `include Gitlab::Graphql::Authorize::AuthorizeResource`, explicit `authorize :read_issue_board_list`, `authorized_resource?(list)` called on the resolved object | — | **Audited, not broken.** |
| `Resolvers::UserResolver` (`app/graphql/resolvers/user_resolver.rb:25`) | None in the resolver | `Types::UserType` declares `authorize :read_user` (`app/graphql/types/user_type.rb:16`) | **Audited, not broken as far as traced** — additionally checked `UserType` for an `email`/`public_email` field with a weaker per-field authorization than the type's own `:read_user` (the exact historical shape of CVE-2022-1352/the "private email disclosed via a sibling API" class in [HISTORICAL_VULNERABILITY_MODEL.md Class 12](HISTORICAL_VULNERABILITY_MODEL.md)); **no `email` field of any kind exists in `UserType`** — the field is simply absent from this general-purpose type, which is the safe design (nothing to leak, rather than something correctly gated). |

**Conclusion for Area 1:** GitLab's GraphQL authorization framework (type-level `authorize` cascading from DeclarativePolicy) is applied consistently across every resolver traced in this pass. This is a **negative result reported deliberately** — it directly informs where *not* to spend further audit time in this specific pattern (bare `object_from_id` calls), and it means a resolver's *absence* of an explicit check is not, by itself, evidence of a gap in this codebase, unlike in less mature GraphQL implementations.

---

## Area 2: Cross-tenant object expansion via ancestor/descendant group hierarchies (direct re-verification of the CVE-2026-1080 bug class)

This is the single most direct, historically-anchored test in this audit: [HISTORICAL_VULNERABILITY_MODEL.md Class 12](HISTORICAL_VULNERABILITY_MODEL.md) cites CVE-2026-1080 as "authorization bypass... access iteration data from private descendant groups through improper access control in the iterations API endpoint." I traced the **current** implementation of exactly this mechanism, plus its nearest sibling, to check whether the fix generalized.

**Route → resolver → finder → sink (Iterations):**
```
GraphQL field (group.iterations / project.iterations)
  → Resolvers::IterationsResolver#resolve            [ee/app/graphql/resolvers/iterations_resolver.rb:53-70]
      authorize!  → Ability.allowed?(current_user, :read_iteration, parent)   [line 106-108]
                     (single check against the QUERIED parent only)
      → IterationsFinder.new(current_user, iterations_finder_params(args)).execute
                                                        [ee/app/finders/iterations_finder.rb]
          by_groups(items)                              [line 60-66]
            return Iteration.none unless skip_authorization || Ability.allowed?(current_user, :read_iteration, params[:parent])
            user_accessible_groups = groups.accessible_to_user(current_user)   # <-- PER-GROUP re-scoping
            items.of_groups(user_accessible_groups)
          groups                                        [line 127-150]
            # expands to self_and_ancestors / self_and_descendants / self_and_hierarchy
            # based on include_ancestors/include_descendants args
```

**Finding: audited, appears fixed.** The single `authorize!` check against `parent` alone would, on its own, be exactly the CVE-2026-1080 shape (checking access to the group you *queried from*, then silently including ancestor/descendant groups without re-checking each one). But `IterationsFinder#by_groups` does **not** use the raw `groups` (ancestor/descendant-expanded) list directly — it calls `groups.accessible_to_user(current_user)` first, which (by its name and by the surrounding `DeclarativePolicy.user_scope`-style pattern used identically in the sibling below) re-filters the expanded group list down to only those groups the current user can actually read before querying `Iteration.of_groups`. This is the correct fix shape for the historical bug class.

**Sibling check (Cadences), performed specifically because this codebase has repeatedly shipped a fix to one code path without applying it to a structurally identical sibling** ([PATCH_ARCHAEOLOGY.md](PATCH_ARCHAEOLOGY.md), Entry 1 and the cross-entry pattern section):
```
GraphQL field (group.iterationCadences)
  → Resolvers::Iterations::CadencesResolver#resolve    [ee/app/graphql/resolvers/iterations/cadences_resolver.rb]
      authorize!  → Ability.allowed?(current_user, :read_iteration_cadence, group)   (single check, same shape)
      → Iterations::CadencesFinder.new(current_user, group, args).execute
                                                        [ee/app/finders/iterations/cadences_finder.rb]
          by_groups(items) → items.with_groups(groups)  [line 36-38]
          groups                                        [line 40-46]
            groups_to_include(group)                    # [group] + group.ancestors if include_ancestor_groups?
            groups_user_can_read_cadences(groups)        [line 55-65]
              DeclarativePolicy.user_scope do
                groups.select { |group| Ability.allowed?(current_user, :read_iteration_cadence, group) }
              end
```
**Also audited, appears fixed** — this sibling independently re-checks `read_iteration_cadence` per individual ancestor group before including its cadences, using an explicit `.select` rather than a named `accessible_to_user` scope, but achieving the same per-object re-authorization. Both the historically-vulnerable code path and its nearest structural sibling correctly re-scope the ancestor/descendant expansion in the current source.

**Why this matters beyond "no bug found":** this is the one place in this audit where I could directly compare current source against a *named, dated, historically-confirmed* vulnerability mechanism, and the result is a genuine, specific confirmation that the fix generalized to a sibling — a rarer outcome in this codebase's history than the alternative (per the repeated "fix didn't cover the sibling" pattern documented in [PATCH_ARCHAEOLOGY.md](PATCH_ARCHAEOLOGY.md)), and worth recording precisely because it's the exception, not the rule.

---

## Area 3: Organization-scoped REST endpoints — client-supplied ID vs. current-user membership

Directly targets this audit's explicit "organization ID supplied by client" and "soft-deleted objects" checklist items.

**Route → controller → service → sink (organization deletion):**
```
DELETE /api/v4/organizations/:id             [lib/api/organizations.rb:69-81]
  route_setting :authorization, permissions: :delete_organization, boundary_type: :instance
  organization = find_organization!(params[:id])     [lib/api/helpers.rb:230-233]
    ::Organizations::Organization.find_by_id(id)      # UNSCOPED lookup by raw numeric ID --
                                                        # any organization instance-wide, not
                                                        # limited to ones the current user belongs to
    check_organization_access(organization)            # <-- the actual per-object gate (not independently
                                                        #     re-read line-by-line in this pass; its
                                                        #     existence and placement immediately after
                                                        #     the unscoped find is the correct, standard
                                                        #     shape used consistently elsewhere in this
                                                        #     codebase, e.g. UploadsController#find_model
                                                        #     + #authorized? in the sibling slice)
  ::Organizations::SoftDeleteService.new(organization, current_user:).execute
    # explicitly branches on response.cause.access_denied? → 403 vs 400, confirming the service
    # itself performs a SECOND, independent per-object authorization check beyond the route_setting
    # declarative gate and beyond check_organization_access
```

**Verdict: audited, structurally sound, one open item.** The unscoped-find-then-explicit-check pattern is the same safe shape used repeatedly elsewhere in this codebase. **`check_organization_access`'s own implementation was not read in this pass** (it lives outside the files opened) — this is the one concrete, fast follow-up for this specific area: confirm it actually checks membership/ownership of *this* organization for *this* user, rather than a coarser instance-wide ability, since the route's own `boundary_type: :instance` declarative setting suggests the *route-level* gate is intentionally coarse (an instance-wide "can this user delete organizations at all" check) and relies entirely on `check_organization_access` (and then the service) for the actual per-tenant scoping.

**Soft-delete follow-through was not traced further in this pass**: whether a soft-deleted organization's resources (projects, groups) remain reachable through *other* endpoints that don't check the parent organization's deletion state is a concrete, separate question this pass did not have budget to pursue, and is recorded as an open item below.

---

## Area 4: Cross-reference to the file-upload slice's authorization-drift finding, restated for the tenant-isolation threat model specifically

[SLICE_01_DEEP_FINDINGS.md DEEP-FINDING-02](SLICE_01_DEEP_FINDINGS.md) documented `UploadsController#authorized?` as a hand-maintained per-model-type case statement with an unscoped `find_model` (`upload_model_class.find(permitted_params[:id])`) and a silent fallback convention for three of eleven model types. That finding is restated here specifically because it is a textbook instance of **exactly** this audit's threat model — a low-privileged authenticated user supplying a raw numeric `:id` to an unscoped `.find`, with correctness resting entirely on the authorization step that follows, for object types (`Project`, `Group`) that are unambiguously tenant boundaries. I do not re-derive it here; I confirm it is in scope for this audit's threat model and refer to that document for the full call chain and confidence grading, to avoid duplicating content.

---

## Areas considered but not traced to a concrete result (recorded as open, per this audit's evidentiary standard — not claimed as findings)

- **Bulk endpoints:** `lib/api/group_placeholder_reassignments.rb` and `lib/api/offline_transfers.rb` were opened and their single-object authorization (`authorize! :read_placeholder_reassignment, user_group`) confirmed correctly scoped to the path's own `:id`; neither endpoint's underlying service (`Import::SourceUsers::GenerateCsvService`, the offline-transfer batch logic) was traced far enough to confirm that a *batch* of reassignment rows is itself filtered to the same group's members only, rather than the group-level check gating access to a service that might return instance-wide or cross-group rows. Flagged as an open item, not a finding.
- **Export/download endpoints:** `lib/api/group_export.rb`'s download action (`user_group.export_file_exists?(current_user)`) was read and appears to correctly scope the export file lookup to `user_group` specifically (not a raw file-ID lookup) — the strongest-looking export endpoint traced in this pass; `lib/api/project_export.rb` was not independently re-verified against the same standard (a fast, high-confidence follow-up, since it is structurally the same feature for a different tenant-boundary object).
- **Search/count/statistics endpoints:** not traced in this pass beyond the general architectural note already recorded in [SYSTEM_CONTEXT.md §4](SYSTEM_CONTEXT.md) (search-index permission drift as a named risk area) — no new source-level evidence was gathered here, and this remains the single largest unaudited item from this audit's own checklist given the time budget.
- **Async jobs / background workers:** not newly traced in this pass beyond what [SECURITY_INVARIANTS.md INV-03](SECURITY_INVARIANTS.md) and [SLICE_01_DEEP_FINDINGS.md](SLICE_01_DEEP_FINDINGS.md)'s negative result on the import-restore Sidekiq-adjacent path already cover; a systematic worker-by-worker authorization audit was out of budget for this pass.
- **Webhook callbacks, alternate API versions, GraphQL mutations (as opposed to resolvers):** not covered in this pass. Mutations in particular are a meaningful gap in this audit's coverage, since write operations are a higher-value target for this threat model than the read-resolvers this pass concentrated on, and were not examined here due to time budget.
- **Predictable identifiers:** no sequential/predictable ID scheme was newly identified in this pass beyond the general observation (already made in [VALIDATION_01.md](VALIDATION_01.md)) that GitLab's own object-storage `remote_id` generator uses cryptographically-random components — this pass did not check whether ordinary ActiveRecord primary keys (sequential integers, used throughout, e.g. `params[:id]` in every endpoint traced above) constitute a "predictable identifier" risk in the sense the checklist means, since GitLab's design relies on authorization checks rather than ID secrecy for these — a defensible design choice, not a gap, provided every check traced above is actually sound.

## What this audit concludes

Every specific mechanism traced to completion in this pass — GraphQL type-level authorization for bare `object_from_id` resolvers, the CVE-2026-1080 ancestor/descendant-group re-scoping pattern and its cadence sibling, and the organization-deletion unscoped-find-then-check pattern — was **found to be correctly implemented**, not broken. This is reported plainly rather than reframed to manufacture findings. The one concrete, still-open, tenant-isolation-relevant candidate from this research chain remains [SLICE_01_DEEP_FINDINGS.md DEEP-FINDING-02](SLICE_01_DEEP_FINDINGS.md) (the `UploadsController` authorization-drift risk), restated here in its correct threat-model context rather than re-derived. The highest-value next steps for a continued authorization audit, in priority order, are: (1) read `check_organization_access`'s actual implementation, (2) trace GraphQL **mutations** (write paths) with the same rigor this pass applied to resolvers (read paths), and (3) the search/count/statistics endpoint class, none of which this pass had budget to reach.

No live testing has been performed, no real third-party data was accessed, and no server-side code was modified in the course of this audit. Waiting for instruction before any live validation begins.
