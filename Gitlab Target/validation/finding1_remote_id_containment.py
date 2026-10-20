#!/usr/bin/env python3
"""
Validation harness for SLICE_01_FINDINGS.md Finding 1
(object_storage.rb#cache_remote_file! -- the two branches for adopting a
client-supplied `remote_id` into GitLab's object storage).

This tests ONLY the pure, deterministic string-manipulation logic of the
non-pending ("branch B" / TMP_UPLOAD_PATH) path, which is the one part of
Finding 1 that does not require a database, a real object-storage backend, or
a running Rails app to evaluate:

    file_path = File.join(TMP_UPLOAD_PATH, remote_object_id)
    file_path = Pathname.new(file_path).cleanpath.to_s
    raise RemoteStoreError, 'Bad file path' unless file_path.start_with?(TMP_UPLOAD_PATH + '/')

Ruby's Pathname#cleanpath and Python's posixpath.normpath / os.path.normpath are not
byte-for-byte identical in every edge case (Pathname#cleanpath is a pure lexical
cleanup with specific rules for leading '..' components: it does NOT collapse a
leading '..' the way normpath sometimes does on some platforms), so this script
implements cleanpath's actual documented algorithm directly rather than relying on
a Python stdlib function that might diverge, and says so.

The "branch A" (PendingDirectUpload.exists? / with_bucket_prefix) path is NOT
testable this way -- it depends on ActiveRecord/database lookup semantics that are
outside this sparse checkout and outside what can be modeled without the real
PendingDirectUpload class body (not located in this research). It is intentionally
left untested here and reported as UNCONFIRMED in VALIDATION_01.md.
"""

TMP_UPLOAD_PATH = "tmp/uploads"  # ObjectStorage::Concern::TMP_UPLOAD_PATH, as commonly named


def cleanpath(path: str) -> str:
    """
    Re-implementation of Ruby's Pathname#cleanpath (non-consider_symlink mode, the
    default), which:
      - splits on '/', drops empty and '.' components,
      - collapses a component followed later by '..' UNLESS that component is itself
        '..' or the path is not absolute and there is nothing left to collapse against
        (in which case the leading '..' is KEPT, not stripped) -- this is the critical
        difference from a naive normpath: cleanpath on a relative path leaves leading
        '..' segments intact rather than resolving them against an assumed cwd.
      - reassembles with '/'.
    This matches Ruby documentation/observed behavior for Pathname#cleanpath.
    """
    is_absolute = path.startswith("/")
    parts = [p for p in path.split("/") if p not in ("", ".")]

    result = []
    for part in parts:
        if part == "..":
            if result and result[-1] != "..":
                result.pop()
            elif is_absolute:
                pass  # '..' above root is discarded for absolute paths
            else:
                result.append("..")  # relative path: leading '..' is preserved, not resolved
        else:
            result.append(part)

    cleaned = "/".join(result)
    if is_absolute:
        cleaned = "/" + cleaned
    return cleaned if cleaned else "."


def cache_remote_file_branch_b(remote_object_id: str):
    """Returns (file_path, raised: bool) exactly like the Ruby method's control flow."""
    file_path = f"{TMP_UPLOAD_PATH}/{remote_object_id}"  # File.join
    file_path = cleanpath(file_path)
    ok = file_path.startswith(TMP_UPLOAD_PATH + "/")
    return file_path, (not ok)  # raised=True means RemoteStoreError('Bad file path')


def test(label, actual, expected):
    status = "PASS" if actual == expected else "FAIL"
    print(f"[{status}] {label}: expected={expected!r} actual={actual!r}")
    return status == "PASS"


if __name__ == "__main__":
    results = []

    print("== Sub-test A: sanity -- a normal remote_id stays inside TMP_UPLOAD_PATH ==")
    fp, raised = cache_remote_file_branch_b("a1b2c3d4-deadbeefcafebabe")
    results.append(test("normal id: no error raised", raised, False))
    results.append(test("normal id: resulting path is correctly namespaced", fp,
                         f"{TMP_UPLOAD_PATH}/a1b2c3d4-deadbeefcafebabe"))

    print()
    print("== Sub-test B: classic ../ traversal attempt via remote_id ==")
    fp, raised = cache_remote_file_branch_b("../../../../etc/passwd")
    print(f"    cleaned path: {fp}")
    results.append(test(
        "../../../../etc/passwd as remote_id IS rejected (cleanpath resolves it out of "
        "TMP_UPLOAD_PATH, and the start_with? check catches that) -- CONFIRMS the branch-B "
        "containment check works correctly against classic relative traversal",
        raised, True,
    ))

    print()
    print("== Sub-test C: does the check correctly reject a SIBLING-prefix confusion? ==")
    # e.g. TMP_UPLOAD_PATH = 'tmp/uploads' -- an attacker-chosen id of
    # '../uploads-evil/x' should NOT be considered inside 'tmp/uploads/'
    fp, raised = cache_remote_file_branch_b("../" + TMP_UPLOAD_PATH.split("/")[-1] + "-evil/x")
    print(f"    cleaned path: {fp}")
    results.append(test(
        "a sibling-directory-name-confusion payload is correctly rejected (start_with? "
        "requires the exact 'TMP_UPLOAD_PATH/' prefix, not just a shared substring)",
        raised, True,
    ))

    print()
    print("== Sub-test D: within-namespace object confusion (the ACTUAL residual risk) ==")
    # This is NOT a traversal payload -- it's a syntactically valid id that legitimately
    # stays inside TMP_UPLOAD_PATH but refers to a DIFFERENT upload than the one the
    # current request's own authorization was issued for. cleanpath+start_with? has
    # NO way to distinguish "my own pending upload's id" from "some other upload's id
    # that also happens to live under tmp/uploads/" -- both pass this check identically.
    my_own_id = "a1b2c3d4-deadbeefcafebabe"
    someone_elses_id = "f9e8d7c6-0000111122223333"  # syntactically identical shape
    fp_mine, raised_mine = cache_remote_file_branch_b(my_own_id)
    fp_theirs, raised_theirs = cache_remote_file_branch_b(someone_elses_id)
    results.append(test(
        "the containment check treats the attacker's OWN legitimate id and ANOTHER "
        "user's id identically -- both pass (raised=False) -- because cleanpath+prefix "
        "is a NAMESPACE check, not an OWNERSHIP check",
        (raised_mine, raised_theirs), (False, False),
    ))
    print("    -> This is the precise, source-confirmed shape of Finding 1's residual risk:")
    print("       the code CANNOT distinguish 'an id I was legitimately issued' from 'an id")
    print("       that happens to exist in the same shared temp namespace' using only this")
    print("       check. Whether an attacker can ever SUPPLY someone else's id (rather than")
    print("       only their own) is the separate, unresolved precondition question from")
    print("       Findings 1/2 (Workhorse JWT gating, id unguessability) -- NOT something")
    print("       this pure-logic test can resolve either way.")

    total = len(results)
    passed = sum(results)
    print()
    print(f"=== {passed}/{total} sub-tests behaved as predicted ===")
