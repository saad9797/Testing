# VALIDATION_01.md — Validation of SLICE_01_FINDINGS.md candidates

Scope authority: [TARGET_SELECTION.md](TARGET_SELECTION.md). **No live testing against any GitLab instance was performed** — this environment has no Ruby, no Docker, and no running GitLab instance (confirmed by direct check at the start of this session), and the user selected "extracted-logic regression tests" as the validation approach rather than installing a full toolchain.

**What "validation" means in this document, precisely:** for each candidate, I extracted the exact algorithm/regex/control-flow read directly from the real source files (cited by path and line in [SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md)), ported it faithfully into small, deterministic Python scripts (kept in [`validation/`](validation/)), and ran them against crafted attacker-shaped inputs and safe control inputs. This proves or disproves the **pure logic** of each candidate conclusively. It cannot prove or disprove anything that depends on the real Rails framework's runtime behavior, a live database, a real object-storage backend, or actual network/deployment topology — those pieces are reported as UNCONFIRMED, with the exact artifact (a runnable script or an RSpec test file) that would resolve them if run against a real instance.

I did not classify anything CONFIRMED without a test actually producing that evidence in this session, and I did not force a FALSE POSITIVE or CONFIRMED verdict where the honest answer is "the pure-logic part checks out, but a live-only precondition remains open."

---

## Candidate 1 (SLICE_01 Finding 1): `remote_id`-based object-storage adoption bypasses the local-path allowlist

**Test artifact:** [`validation/finding1_remote_id_containment.py`](validation/finding1_remote_id_containment.py) (branch B / `TMP_UPLOAD_PATH`, pure logic — executed, 5/5 sub-tests passed) + [`validation/finding2_middleware_failopen.py`](validation/finding2_middleware_failopen.py) (the JWT-gating precondition, executed, 3/3 passed) + [`validation/finding1_branchA_pending_upload_spec.rb`](validation/finding1_branchA_pending_upload_spec.rb) (branch A / `PendingDirectUpload` ownership — **not executed**, no Ruby/DB available).

**What was proven:**
- The `cache_remote_file!` **non-pending branch** (`File.join(TMP_UPLOAD_PATH, remote_object_id)` → `Pathname#cleanpath` → `start_with?` check) **correctly rejects** classic relative-traversal payloads (`../../../../etc/passwd`) and sibling-directory-name-confusion payloads (`../uploads-evil/x`). This part of the original SLICE_01 write-up ("branch B ... has a canonicalize+prefix check that constrains the result") is **CONFIRMED CORRECT** as pure logic — i.e., this specific sub-mechanism is **not** a traversal bug.
- That same branch **cannot distinguish** a syntactically-valid `remote_id` the attacker legitimately owns from an equally syntactically-valid `remote_id` belonging to someone else — both pass the containment check identically, because `cleanpath`+`start_with?` is a **namespace** check, not an **ownership** check. This is the real, precise shape of the residual risk, and it is now demonstrated rather than merely asserted.
- The `Multipart` middleware (`lib/gitlab/middleware/multipart.rb`) **fails open**: when the trusted `HTTP_GITLAB_WORKHORSE_MULTIPART_FIELDS` header is absent, it passes the request straight through to the Rails app unchanged, rather than rejecting it — confirmed by faithfully porting its exact control flow.

**What remains unresolved (cannot be tested without a live instance):**
1. Whether `ObjectStorage::PendingDirectUpload.exists?(storage_location_identifier, remote_object_id)` (the "pending" branch A, used for final-store-path direct uploads) binds the pending record to the specific model/user/request that created it, or is a bare existence check across the whole storage location. The class's exact file was not located in the sparse checkout used for this research, but a later session located enough external documentation (a cleanup-worker description in GitLab's own issue tracker) to confirm `PendingDirectUpload` is **backed by a Redis hash, not a database table**, keyed by `(storage_location_identifier, id)` — i.e. per-uploader-*class* (e.g. all `:artifacts` uploads share one namespace), not per-user, per-project, or per-request. This **sharpens rather than closes** the open question: it confirms there is no per-request ownership dimension built into the key at all, so the residual risk is entirely about whether the cryptographically-random `id` value can ever be observed by a user other than the one it was issued to (not addressed by this fact, and not resolvable without either a live instance or more targeted source hunting for anywhere the id might be echoed back to a client). **The exact RSpec test that would resolve this is still provided** in [`finding1_branchA_pending_upload_spec.rb`](validation/finding1_branchA_pending_upload_spec.rb) but was not run.
2. Whether any real GitLab deployment ever exposes Rails/Puma reachable without every request first passing through gitlab-workhorse (this is what makes the fail-open behavior above matter in practice, or not matter at all if the network topology genuinely never allows it). This is a deployment/infrastructure question, not resolvable from source or from a pure-logic script under any circumstance.
3. Whether a `remote_id` value, once issued to one user's legitimate upload flow, is ever guessable/observable/reusable by a different user in practice (the ID is `Digest::SHA2.hexdigest(SecureRandom.uuid)`-based for the final-path case and `CarrierWave.generate_cache_id + SecureRandom.hex`-based for the tmp case — both are large, effectively unguessable per source review, but no entropy/predictability test was run against the real generator).

**Classification: UNCONFIRMED.**
The pure-logic mechanism this finding describes is real and precisely characterized (proven, not just argued), but every path to actual exploitability depends on at least one of the three open questions above, none of which a source-level or pure-logic test can settle. This is not a FALSE POSITIVE — the containment check demonstrably has no ownership semantics — but it is also not CONFIRMED, because no concrete attacker capability to reach either open precondition was established.

---

## Candidate 2 (SLICE_01 Finding 2): the Workhorse-JWT trust boundary is a network-topology assumption, not a framework-enforced one

**Test artifact:** [`validation/finding2_middleware_failopen.py`](validation/finding2_middleware_failopen.py) — executed, 3/3 sub-tests passed.

**What was proven:** the middleware's control flow, ported faithfully from the actual Ruby source read in this session, does exactly what Finding 2 claimed: on a missing trusted header, it calls straight through to the rest of the app with the client-supplied `params['file']['remote_id']` etc. completely unexamined. There is no code-level check anywhere in this middleware that verifies "was this request actually proxied through Workhorse" beyond "is this one specific header present" — and the header's mere *presence* isn't independently re-verified against anything else in the request (its *contents*, i.e. the JWT itself, are cryptographically verified only in the branch that already assumes the header is legitimate).

**What remains unresolved:** this finding's entire real-world relevance is the deployment/network-topology question in item 2 of Candidate 1 above — whether Rails is ever reachable directly. That is fundamentally not a question a source-level or logic-level test can answer; it requires either a live instance with a deliberately misrouted/exposed Puma port, or authoritative documentation of GitLab's own deployment guarantees (Omnibus/Helm chart network policy) that was not researched in this pass.

**Classification: UNCONFIRMED.**
The code-level mechanism (fail-open on missing header) is proven, not speculative. Whether it is reachable in any real deployment is the single open question, and it is a live/infrastructure question by nature — this finding cannot graduate past UNCONFIRMED through source analysis or logic testing alone, no matter how the code-level mechanism is characterized.

---

## Candidate 3 (SLICE_01 Finding 3): the Rack-level path-traversal middleware is body-blind and permanently exempts 12 named parameters

**Test artifact:** [`validation/finding3_path_traversal_regex.py`](validation/finding3_path_traversal_regex.py) — executed, 7/7 sub-tests passed.

**What was proven:**
- The middleware's own function signature and control flow (ported faithfully) **structurally cannot** receive or inspect a request body — it operates exclusively on `request.fullpath`/`request.GET`. This is a direct structural proof, not an inference: the ported function has no body/POST-data parameter at all, exactly mirroring the real Ruby method.
- The 12-name exemption list is unconditional: an identical traversal payload (`../../../../etc/passwd`) placed under an exempted parameter name (`description`) is **not** flagged by the middleware, while the same payload under a non-exempted name **is** flagged — demonstrated side-by-side with the same underlying regex.
- **A genuinely new result, not present in the original SLICE_01 write-up:** modeling `Gitlab::Utils.decode_path` as a single-pass percent-decode (the most plausible reading of its source comment, since its exact implementation could not be located — see the script's docstring for this explicit caveat) shows that a **double-percent-encoded** traversal payload (`%252e%252e%252f...`) survives the check-path-traversal helper's single decode pass unflagged. This directly demonstrates the double-decode risk that [SECURITY_INVARIANTS.md INV-02](SECURITY_INVARIANTS.md) predicted architecturally, now shown as a concrete input/output pair rather than a theoretical concern — **conditional on the single-decode modeling assumption being correct**, which was not verified against the real `Gitlab::Utils.decode_path` source (not located in this session; flagged honestly in the script itself).

**What remains unresolved:** whether any current GitLab feature in the file-upload/download slice actually builds a filesystem path from a request-body field or from one of the 12 exempted parameter names, without its own independent `check_path_traversal!` call. This session's direct reads of the three concrete call sites in this slice (`UploadsActions#show`, `UploaderFinder`, `ObjectStorage::Concern#retrieve_from_store!`) found all three call the helper directly, independent of this middleware — so **no live sink was found**, matching what [SLICE_01_FINDINGS.md](SLICE_01_FINDINGS.md) already stated. Whether `Gitlab::Utils.decode_path` really is single-pass (making the double-encoding sub-result meaningful) was also not confirmed against real source.

**Classification: UNCONFIRMED**, with two sub-parts to be precise:
- The body-blindness and 12-name exemption structural claims: **CONFIRMED** as an accurate description of the code's actual, deterministic behavior (proven by direct, faithful logic execution against the real read source) — but confirmed as an **architectural characteristic**, not confirmed as an **exploitable vulnerability**, since no sink was found to attach it to.
- The double-encoding bypass sub-finding: **UNCONFIRMED**, pending verification of the `decode_path` modeling assumption and, independently, discovery of any sink that performs a second decode.

Overall candidate classification: **UNCONFIRMED** (the middleware behavior is proven; exploitability is not, for lack of a discovered sink).

---

## Candidate 4 (SLICE_01 Finding 4): one route family has a materially looser filename constraint than its siblings

**Test artifact:** [`validation/finding4_route_constraint.py`](validation/finding4_route_constraint.py) — executed, 4/4 sub-tests passed.

**What was proven:**
- The routing-layer inconsistency itself is real and exactly as described: for a literal, unencoded `../../../../etc/passwd`-shaped segment, the strict `[^/]+` constraint used on 5 of 6 upload-serving routes rejects the match (the request would 404 before the controller ever runs), while the loose `.+` constraint used only on the appearance/branding route accepts it and would forward the request to the controller.
- **A genuinely new result that materially changes this finding's practical significance:** testing the same payload with the slash percent-encoded (`%2F` instead of `/`) shows that **if** Rails/Rack matches route-segment constraints against the raw, not-yet-decoded segment (Branch B in the script), then the "stricter" `[^/]+` constraint is satisfied just as easily as the loose one, because the encoded string contains no literal `/` character at all — collapsing the routing-layer distinction to irrelevant, and making `check_path_traversal!`'s decode-then-check the sole real defense on **every** route in the table, not just the loose one. If instead Rack/Rails decodes `%2F` before constraint matching (Branch A), the strict routes remain genuinely stricter and the original finding stands at full strength.

**What remains unresolved:** which of Branch A or Branch B actually describes the deployed Rack/ActionDispatch version's behavior. This is a well-known, version-and-configuration-dependent detail of the Rack/Rails request-routing stack (whether `%2F`/other percent-encoded reserved characters are decoded before or after route-segment constraint matching) that cannot be determined from the GitLab application source alone — it lives in Rack/ActionDispatch, which is a dependency, not part of this research's checkout, and ultimately it is the kind of thing that is fastest and most reliably answered by sending one actual HTTP request to a live instance and observing whether a `%2F`-containing filename reaches the controller (observable via the 404-vs-400-vs-200 response, or via `check_path_traversal!`'s log line) on one of the strict routes.

**Classification: UNCONFIRMED.**
The core routing-table inconsistency is proven and real. Whether it is *practically exploitable-in-a-way-the-loose-route-isn't-already* depends entirely on the unresolved Rack-decoding-order question — this finding cannot be pushed to CONFIRMED (needs the live/Rack-version answer) or FALSE POSITIVE (the inconsistency is real regardless of which branch is true) from this session's evidence.

---

## Summary table

| Candidate | Pure-logic mechanism | Live/deployment precondition needed | Classification |
|---|---|---|---|
| 1. `remote_id` allowlist bypass | Proven: namespace-check, not ownership-check | `PendingDirectUpload` ownership semantics; network reachability of Rails without Workhorse; `remote_id` predictability | **UNCONFIRMED** |
| 2. Workhorse-JWT boundary is topology-only | Proven: middleware fails open on missing header | Whether that topology gap is ever real in a deployed instance | **UNCONFIRMED** |
| 3. Path-traversal middleware body-blind + exemption list | Proven: structurally can't see bodies; exemption list is unconditional; double-decode gap shown under a stated modeling assumption | A concrete sink using an exempted param/body field for a file path (none found); confirmation of `decode_path`'s real implementation | **UNCONFIRMED** |
| 4. Route constraint inconsistency | Proven: constraint difference is real for literal payloads | Rack's percent-decode-vs-constraint-matching order (live-instance-only question) | **UNCONFIRMED** |

No candidate reached CONFIRMED or FALSE POSITIVE in this pass. This is the expected, honest outcome of "extracted-logic regression tests" as a validation method for a slice whose remaining open questions are, in every one of the four candidates, ultimately live-instance/deployment/dependency-version questions rather than pure-application-logic questions — which is itself useful information: it means the four candidates in this slice have already been narrowed, by source reading alone, down to the smallest remaining testable surface, and the next unit of work with the highest expected payoff is standing up an actual instance (Ruby/Docker toolchain) specifically to answer the four boxed precondition questions above, rather than further source analysis.

## What would resolve each remaining UNCONFIRMED, in priority order

1. **Candidate 4** first — cheapest to resolve (one crafted HTTP request to any real GitLab instance's `-/system/appearance/favicon/1/x` vs. an equivalent non-appearance upload route with a `%2F`-containing filename segment, observing the response code).
2. **Candidate 2 / Candidate 1's topology question** — requires deploying (or documenting) the actual network path between a client and Puma/Rails to determine if Workhorse can ever be bypassed.
3. **Candidate 1's `PendingDirectUpload` ownership question** — requires the real Ruby class body and, ideally, running the provided (unexecuted) RSpec artifact.
4. **Candidate 3's `decode_path` modeling assumption** — requires reading the actual `Gitlab::Utils.decode_path` source (not located in this session) and, if a sink is ever found elsewhere in the app, re-running the double-encoding sub-test against the real implementation.

No live testing has been performed against any instance in this session. Waiting for instruction before any of the above live-validation steps begin.
