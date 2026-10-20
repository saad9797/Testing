# SLICE_01_DEEP_FINDINGS.md — File upload/download, second pass

Scope authority: [TARGET_SELECTION.md](TARGET_SELECTION.md). No exploitation attempted. This is a **second pass** over the same slice as [SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md) and [VALIDATION_01.md](VALIDATION_01.md), explicitly setting aside all four previously-identified mechanisms (local-path allowlist skip on `remote_id`, Workhorse-JWT topology assumption, Rack-middleware body-blindness/exemption-list, route filename-constraint inconsistency) and asking "what else could break," working through the expanded checklist the task specified (alternate execution paths, encoding/canonicalization, state-machine and ownership-transition issues, cache/async/race/partial-failure behavior, permission inheritance, import/export, administrative paths, etc.).

Two genuinely new source-grounded findings resulted, plus one important **negative result** (an avenue I pursued in depth, expecting to find a bug, that turned out to be already defended by a mechanism I hadn't previously examined) and one minor, policy-excluded observation. I report the negative result explicitly because it is the direct product of chasing "alternate execution paths" and "import/export functionality" from the checklist, and because it surfaces a general-purpose defense (`GitlabUploader#protect_from_path_traversal!`) that is directly relevant to how the two new findings were found and scoped.

---

## DEEP-FINDING-01: `remote_id` object-storage adoption bypasses not only the local-path allowlist, but the *entire* universal, TOCTOU-hardened CarrierWave path-traversal hook that protects every other uploader in the application

This is a **different mechanism** from SLICE_01 Finding 1 (which was about `UploadedFile.from_params` skipping `File.realpath`+`allowed_path?`). This finding is about a second, independent, previously-unexamined safety net — `GitlabUploader`'s own base-class callback hooks — and shows that the `remote_id` code path evades that one too, for a distinct, more fundamental reason (a missing `super` call, not a missing conditional branch).

**Invariant:** every uploader, regardless of model type or storage backend, has its `filename`/`cache_dir`/`work_dir`/`store_dir` checked for path-traversal sequences immediately before both the CarrierWave `cache` step and the `store` step — the base class comment is explicit about why both: *"Re-check at store time: filename/store_dir can change between cache and store (TOCTOU)."* This is GitLab's own, deliberately-designed, TOCTOU-aware answer to exactly the class of bug this whole slice is about.

**Entry point:** any endpoint that reaches `ObjectStorage::Concern#cache!` with a `remote_id`-bearing `UploadedFile` — same entry points as SLICE_01 Finding 1 (`lib/api/project_import.rb`'s `file.remote_id` param, and by the same mechanism any other Workhorse-direct-upload endpoint).

**Attacker-controlled input:** the `remote_id` string (see Finding 1/2 in [SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md) for the preconditions under which this is attacker-reachable at all).

**Exact call chain:**
```
GitlabUploader (app/uploaders/gitlab_uploader.rb:53-55)
  before :cache, :protect_from_path_traversal!
  before :store, :protect_from_path_traversal!
                                                  # ^ registered on EVERY GitlabUploader subclass,
                                                  #   including FileUploader/ObjectStorage::Concern

ObjectStorage::Concern#cache!(new_file)          [app/uploaders/object_storage.rb:499-507]
  if new_file.is_a?(::UploadedFile) && new_file.remote_id.present?
    return cache_remote_file!(new_file.remote_id, new_file.original_filename)
      # <-- RETURNS HERE. `super` (CarrierWave::Uploader::Cache#cache!, the method that
      #     actually fires the `before :cache` ActiveSupport::Callbacks chain) is NEVER
      #     REACHED on this branch. protect_from_path_traversal! never runs for :cache.
  end
  super   # only reached when remote_id is NOT present -- the :cache hook fires normally here

cache_remote_file!(remote_object_id, original_filename)   [app/uploaders/object_storage.rb:552-579]
  # builds file_path from remote_object_id (branch A or B, per SLICE_01 Finding 1),
  # then directly assigns:
  @cache_id = "force-to-use-cache"
  @file = CarrierWave::Storage::Fog::File.new(self, storage_for(Store::REMOTE), file_path)
  # -- @file is now pointing at whatever object `file_path` (derived from the
  #    attacker-influenced remote_object_id) resolves to, WITHOUT protect_from_path_traversal!
  #    ever having inspected `file_path`/`remote_object_id` at all.

ObjectStorage::Concern#store!(new_file = nil)     [app/uploaders/object_storage.rb:509-516]
  self.object_store = Store::REMOTE if self.class.direct_upload_to_object_store?
  super   # <-- THIS super IS always called, so `before :store, :protect_from_path_traversal!`
          #     DOES fire here.

protect_from_path_traversal!(file)                [app/uploaders/gitlab_uploader.rb:207-218]
  PROTECTED_METHODS.each do |method|   # filename, cache_dir, work_dir, store_dir
    Gitlab::PathTraversal.check_path_traversal!(self.send(method))
  end
  # These four methods derive their values from `secret`/`identifier`/`dynamic_segment`
  # (i.e. from the uploader's own model-bound state), NOT from `remote_object_id` or
  # `file_path` -- the string that was actually used to select which Fog object
  # `@file` now points at is never among the values this hook inspects.
```

**Security boundary:** "every value that ends up selecting a filesystem/object-storage location, from every uploader, passes through the same traversal check, at both points in the CarrierWave lifecycle where it could change." This boundary is enforced universally at the `GitlabUploader` base-class level — a stronger, more centralized guarantee than the per-call-site `check_path_traversal!` calls examined in the first pass.

**Broken assumption:** that overriding `cache!`/`store!` inside `ObjectStorage::Concern` (a module included by every object-storage-capable uploader) would necessarily still exercise the base class's `before`-hook chain, since the hooks are registered via `before :cache`/`before :store` (CarrierWave/ActiveSupport callback macros that wrap the *named public methods* `cache!`/`store!`). `cache!`'s remote_id branch explicitly `return`s before calling `super`, which is precisely the code path that would otherwise invoke the wrapped, callback-chain-triggering original method — this is a standard, easy-to-make Ruby mistake (an early return in an overridden method silently skipping inherited `before`/`after` callback behavior), not a deliberately-disabled check.

**Expected behavior:** `protect_from_path_traversal!` should inspect whatever value(s) actually determine the object-storage location being adopted (`remote_object_id`/`file_path`) on the `remote_id` branch, exactly as it inspects `filename`/`store_dir` on every other branch.

**Actual behavior:** the `:cache`-time check never runs on this branch at all (no `super` call), and the surviving `:store`-time check runs but inspects a set of values (`filename`, `cache_dir`, `work_dir`, `store_dir`) that are computed from unrelated uploader state (`secret`/`identifier`) rather than from `remote_object_id`/`file_path` — meaning the attacker-influenced value is never actually inspected by this mechanism at either callback point, even though the hook itself does fire once.

**Required preconditions:** identical to SLICE_01 Finding 1/2 — an attacker-reachable `remote_id` value, which depends on the unresolved network-topology and `PendingDirectUpload`-ownership questions already documented as UNCONFIRMED in [VALIDATION_01.md](VALIDATION_01.md).

**Potential impact:** does not by itself create a new impact beyond what Finding 1 already described (object/upload confusion within the storage bucket) — but it **removes a defense-in-depth layer** that this research had not previously accounted for, meaning Finding 1's risk should not be discounted on the theory that "surely some other general mechanism would catch this" — this finding demonstrates concretely that no other mechanism does.

**Confidence:** Medium-High on the mechanism itself (this is a direct, traceable control-flow fact from reading `object_storage.rb` and `gitlab_uploader.rb` together — not an inference); Low on independent exploitability, for the same unresolved-precondition reasons as Finding 1.

**Exact source locations:** `app/uploaders/gitlab_uploader.rb:8,53-55,207-218` (`PROTECTED_METHODS`, the two `before` hook registrations, `protect_from_path_traversal!`); `app/uploaders/object_storage.rb:499-507` (`cache!`, the early return), `:509-516` (`store!`, the unconditional `super`), `:552-579` (`cache_remote_file!`).

**Why the issue is exploitable (if Finding 1/2's preconditions hold):** because this is a second, independent confirmation that nothing in the request path re-validates the attacker-influenced value — it forecloses the natural objection "even if the local-path allowlist is skipped, surely the general-purpose CarrierWave hook would still catch a traversal attempt," which this trace shows is false for this specific branch.

---

## DEEP-FINDING-02: `UploadsController#authorized?` is a hand-maintained, per-model-type authorization table with a silent fallback convention, structurally distinct from (and a different instance of the same class of risk as) the GraphQL/REST authorization drift already documented in the Authorization slice

**Invariant:** every model type servable through the generic `UploadsController` has an authorization rule that is (a) actually reachable for that type and (b) correctly scoped to the loaded object, not to some structurally-similar-looking but wrong ability name.

**Entry point:** `GET /uploads/-/system/:model/...` for any `:model` value present in `UploadsController::MODEL_CLASSES` — this is the **first close read of this controller** in this research chain (the first pass examined the `UploadsActions` concern it includes, but not this controller's own `find_model`/`authorized?`/`MODEL_CLASSES` logic).

**Attacker-controlled input:** the `:model` route segment (constrained by each route's own regex, e.g. `/personal_snippet|user|abuse_report/`) and `:id`.

**Exact call chain:**
```
config/routes/uploads.rb  -> UploadsController#show (via UploadsActions#show)
  find_model                                    [app/controllers/uploads_controller.rb:47-49]
    upload_model_class.find(permitted_params[:id])   # UNSCOPED .find(id) -- no project/group/
                                                       # namespace scoping at the lookup step itself;
                                                       # all scoping happens AFTER the fact, in authorized?
  authorize_access! (before_action, :show only)  [uploads_controller.rb:29,80-82]
    render_unauthorized unless authorized?
  authorized?                                    [uploads_controller.rb:51-78]
    case model
    when Note                              -> can?(current_user, :read_project, model.project)
    when Snippet, ProjectSnippet           -> can?(current_user, :read_snippet, model)
    when User                              -> (secret-gated; see below)
    when Appearance                        -> true
    when Projects::Topic                   -> true
    when ::AlertManagement::MetricImage    -> can?(current_user, :read_alert_management_metric_image, model.alert)
    when ::Achievements::Achievement       -> true
    when Organizations::OrganizationDetail -> can?(current_user, :read_organization, model.organization)
    else                                   -> can?(current_user, :"read_#{model.class.underscore}", model)
                                               # ^ THIS branch is what silently handles Project, Group,
                                               #   and AbuseReport today (none of the three has its own
                                               #   explicit `when`), by convention-based ability-name
                                               #   construction rather than an explicit, reviewable mapping.
```

**Security boundary:** the boundary between "this upload's containing object permits the current user to read it" and "any object of this type." The unscoped `.find(id)` in `find_model` means this boundary is enforced *entirely* by `authorized?` — there is no defense-in-depth from the lookup step itself (unlike, say, a Finder-scoped query that would return `nil` for an out-of-scope object before authorization is even considered).

**Broken assumption:** that every entry in `MODEL_CLASSES` (a hash literal, trivially extensible) will always be given an explicit, reviewed `when` clause in `authorized?` before being shipped, and that the implicit `else` convention (`:"read_#{model.class.underscore}"`) will always happen to name a real, correctly-scoped DeclarativePolicy ability for whatever model is added next. This is not enforced by any test, type system, or linter visible in the files read — it is a convention that three of the eleven current entries (`Project`, `Group`, `AbuseReport`) already silently rely on rather than being explicitly listed, which is itself evidence the convention is doing real, unreviewed work today, not just standing ready for hypothetical future use.

**Expected behavior:** either an explicit `when` for every `MODEL_CLASSES` entry (making a missing/wrong mapping a visible gap in the case statement), or a structural test asserting `MODEL_CLASSES.keys` and the `case` statement's handled types stay in sync.

**Actual behavior:** three of eleven current model types are handled only by the implicit, convention-based `else` branch; verified for this pass that `:read_project`, `:read_group` are the conventionally-expected, plausible ability names (not confirmed against the actual `ProjectPolicy`/`GroupPolicy` ability lists in this pass — a fast, concrete follow-up), and `AbuseReportPolicy`'s `:read_abuse_report` ability's exact scoping was not independently examined in this pass.

**Required preconditions:** a future (or, if the policy-name assumption above is ever wrong, a *current*) mismatch between a `MODEL_CLASSES` entry and either (a) the existence of a correctly-scoped `read_#{underscore}` ability for it, or (b) that ability's actual scoping being as strict as `authorized?`'s explicit branches are for structurally similar types (`Note`→`read_project` scopes through the *parent* object deliberately, for example — a model added later whose "obvious" ability name checks the object itself rather than its true containing-visibility object would be a silent under-scoping, exactly the shape of bug this whole controller's design invites).

**Potential impact:** ranges from none (if the convention always happens to hold, as it appears to for the three current implicit cases) to unauthorized read access to a private object's upload, if a future model addition's conventional ability name doesn't provide the same strength of scoping as this controller's explicit, hand-reviewed branches do.

**Confidence:** Medium on the architectural risk being real and precisely characterized (directly read); Low on any *current* instance of it being wrong, since the three implicit cases were not independently disproven to be correctly scoped in this pass — this is reported as a structural risk pattern with concrete, named current examples of the pattern in live use, not as a confirmed current bypass.

**Exact source locations:** `app/controllers/uploads_controller.rb:9-22` (`MODEL_CLASSES`), `:47-49` (`find_model`), `:51-78` (`authorized?`, especially the `else` branch at line 76).

**Why the issue is exploitable (if a future/current mismatch exists):** because `find_model`'s unscoped lookup provides zero independent containment, `authorized?`'s `else` branch is the *only* thing standing between an unscoped-by-ID lookup and the response — and that branch's correctness for any given model type has never been explicitly, visibly asserted for that type, only inherited by naming convention.

---

## Negative result (recorded per instruction, since it directly follows from working the "import/export functionality" and "alternate execution paths" checklist items and materially affects how DEEP-FINDING-01 should be read)

**Avenue pursued:** whether `lib/gitlab/import_export/uploads_manager.rb#add_upload` — which restores uploads from an **attacker-authored project-export archive** into a newly-imported project — could let a crafted archive directory/filename structure produce a traversal-capable `identifier` (via `FileUploader.extract_dynamic_path`'s regex extraction from the on-disk restored path) that reaches `UploadService#execute` → `uploader.store!(file)` unchecked.

**What was found:** `UploadService#execute` calls the **real, un-overridden** CarrierWave `uploader.store!(file)` (the `File.open(upload, 'r')` object is a plain `File`, not an `UploadedFile` with `remote_id`), so `ObjectStorage::Concern#cache!`'s `remote_id`-branch early-return (the mechanism DEEP-FINDING-01 exploits) does **not** apply here — `cache!` falls through to `super`, and both `before :cache` and `before :store` hooks from `GitlabUploader#protect_from_path_traversal!` fire normally. This import-restore path is therefore, on this pass's reading, **already covered** by the same universal hook DEEP-FINDING-01 shows is skipped elsewhere. **No finding is reported for this avenue** — it is recorded here specifically because it demonstrates the value of DEEP-FINDING-01's central fact (which paths reach the universal hook and which don't) as a general triage tool for the rest of this slice, and because [PATCH_ARCHAEOLOGY.md](PATCH_ARCHAEOLOGY.md)'s open question about whether import-related upload sinks were ever hardened is now answered, for this specific sink, in the affirmative.

---

## Minor observation, not raised to a full finding (policy-relevant, not bounty-eligible)

`UploadsController#render_unauthorized` (`uploads_controller.rb:96-102`) returns a 404 when `current_user || workhorse_authorize_request?`, and calls `authenticate_user!` (redirect-to-login) otherwise — meaning an authenticated-but-unauthorized request and an unauthenticated request to the same, already-confirmed-to-exist private upload produce distinguishably different responses. This is real and directly read from source, but it is precisely the class of finding [TARGET_SELECTION.md](TARGET_SELECTION.md)'s program policy excludes ("Reports where an attacker can validate a guess... An API route returning different status codes depending on if a private path exists or not"), and in any case this specific branch is only reached after `find_model` has already succeeded (i.e., existence is already established before this code runs, so the status-code difference leaks authentication state, not existence) — recorded here for completeness per the instruction to search broadly, not elevated to a full finding given its policy status and marginal information value.

---

## What was not done in this pass

- The exact DeclarativePolicy ability definitions for `:read_project`, `:read_group`, and `:read_abuse_report` (DEEP-FINDING-02's implicit-`else` cases) were not independently read to confirm they scope as strictly as the controller's explicit branches — the fastest concrete follow-up for that finding.
- A background/async object-storage migration worker (moving uploads between local and remote storage post-hoc) was suspected to exist and searched for, but the search could not complete in this session (large-repository grep timeout, `app/workers` not in the sparse checkout) — this remains an open, unexplored avenue for a future pass, not ruled out.
- Content-type/format-confusion angles (`set_request_format_from_path_extension`'s full mapping behavior beyond the one documented `.js`→`:text` case) were flagged in the first pass as an open question and were not revisited in this pass.
- No live testing was performed against any instance for either new finding.

No exploitation has been attempted. Waiting for instruction before any live validation begins.
