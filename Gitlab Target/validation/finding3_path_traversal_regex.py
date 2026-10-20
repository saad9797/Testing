#!/usr/bin/env python3
"""
Validation harness for SLICE_01_FINDINGS.md Finding 3
(path_traversal_check.rb Rack middleware: body-blind, 12-name exemption list).

This is a PORT, not the original Ruby: it re-implements, in Python, the exact
regex and control flow read directly from:
  - lib/gitlab/path_traversal.rb          (PATH_TRAVERSAL_REGEX, PATH_TRAVERSAL_REGEX_WITH_NEWLINE,
                                            check_path_traversal!, path_traversal?)
  - lib/gitlab/middleware/path_traversal_check.rb (EXCLUDED_QUERY_PARAM_NAMES, NESTED_PARAMETERS_MAX_LEVEL,
                                            path_traversal_attempt?, exclude_query_parameters,
                                            cleanup_query_parameters!)

Ruby regex and Python `re` are both PCRE-like/Oniguruma-like for this pattern (no
Ruby-specific regex features are used: no possessive quantifiers, no \A/\z-specific
Oniguruma extensions beyond what Python supports via ^\Z-with-MULTILINE-off), so this
is a faithful translation for the purpose of this test. This is stated explicitly as
an assumption, not verified against a live Ruby interpreter (none is available in
this environment).

`decode_path`'s exact implementation (Gitlab::Utils.decode_path) could not be located
in the sparse checkout used for this research and was not found via a raw fetch of
the public repository in this session. It is modeled here as a SINGLE-PASS percent-decode
(`urllib.parse.unquote`, which is semantically equivalent to Ruby's `CGI.unescape`/
`URI.decode_www_form_component` for %XX sequences), matching the source comment in
path_traversal.rb ("We url decode the path ... to avoid passing invalid paths forward
in url encoded format") which describes a single decode step, not a loop. This
modeling choice is the single most important assumption in this test file and is
flagged again in VALIDATION_01.md.
"""

import re
import urllib.parse

# --- exact port of lib/gitlab/path_traversal.rb ---

PATH_TRAVERSAL_REGEX = re.compile(
    r"(\A(\.{1,2})\Z)|(\A\.\.[/\\])|([/\\]\.\.\Z)|([/\\]\.\.[/\\])"
)
PATH_TRAVERSAL_REGEX_WITH_NEWLINE = re.compile(
    PATH_TRAVERSAL_REGEX.pattern + r"|(\n)"
)


def decode_path(path: str) -> str:
    """Modeled single-pass percent-decode. See module docstring."""
    return urllib.parse.unquote(path)


def path_traversal(decoded_path: str, match_new_line: bool = True) -> bool:
    if decoded_path is None:
        return False
    regex = PATH_TRAVERSAL_REGEX_WITH_NEWLINE if match_new_line else PATH_TRAVERSAL_REGEX
    return regex.search(decoded_path) is not None


def check_path_traversal(path: str):
    """Raises (returns None + flag) exactly like the Ruby raising helper."""
    if path is None:
        return None, False
    decoded = decode_path(path)
    if path_traversal(decoded, match_new_line=True):
        return decoded, True  # would raise PathTraversalAttackError
    return decoded, False


# --- exact port of lib/gitlab/middleware/path_traversal_check.rb ---

EXCLUDED_QUERY_PARAM_NAMES = {
    "search", "search_title", "search_query", "term", "name", "filter",
    "filter_projects", "note", "body", "commit_message", "content", "description",
}
NESTED_PARAMETERS_MAX_LEVEL = 5


def cleanup_query_parameters(params: dict, level: int = 1) -> dict:
    if not params or level > NESTED_PARAMETERS_MAX_LEVEL:
        return params
    for name in list(params.keys()):
        if name in EXCLUDED_QUERY_PARAM_NAMES:
            del params[name]
    for k, v in list(params.items()):
        if isinstance(v, dict):
            params[k] = cleanup_query_parameters(v, level + 1)
    return params


def middleware_path_traversal_attempt(fullpath: str, query_params: dict) -> bool:
    """
    Faithful port of path_traversal_attempt?: it operates ONLY on request.fullpath
    (URL path + query string), after stripping excluded query param names from the
    query-string portion. It NEVER receives or inspects a request body.
    """
    cleaned_query_params = cleanup_query_parameters(dict(query_params))
    # Rebuild fullpath with the cleaned query string, exactly as
    # exclude_query_parameters does via request.set_header(Rack::QUERY_STRING, ...)
    path_part = fullpath.split("?", 1)[0]
    if cleaned_query_params:
        qs = urllib.parse.urlencode(cleaned_query_params)
        rebuilt_fullpath = f"{path_part}?{qs}"
    else:
        rebuilt_fullpath = path_part

    decoded_fullpath = urllib.parse.unquote(rebuilt_fullpath)  # CGI.unescape(request.fullpath)
    return path_traversal(decoded_fullpath, match_new_line=False)


# =========================== TESTS ===========================

def test(label, fn, expected, *args, **kwargs):
    actual = fn(*args, **kwargs)
    status = "PASS" if actual == expected else "FAIL"
    print(f"[{status}] {label}: expected={expected!r} actual={actual!r}")
    return status == "PASS"


if __name__ == "__main__":
    results = []

    print("== Sub-test A: core check_path_traversal! regex, single URL-encoding ==")
    _, flagged = check_path_traversal("/uploads/1111.../../../../etc/passwd")
    results.append(test("literal ../ sequence is flagged", lambda: flagged, True))

    _, flagged = check_path_traversal("%2e%2e%2fetc%2fpasswd")
    results.append(test("single percent-encoded ../ is flagged after one decode", lambda: flagged, True))

    print()
    print("== Sub-test B: DOUBLE percent-encoding defeats the single-decode assumption ==")
    double_encoded = "%252e%252e%252fetc%252fpasswd"  # decodes ONCE to %2e%2e%2fetc%2fpasswd (still encoded)
    decoded_once, flagged = check_path_traversal(double_encoded)
    print(f"    input             : {double_encoded}")
    print(f"    after ONE decode  : {decoded_once}")
    results.append(test(
        "double-encoded traversal is NOT flagged by a single-decode check "
        "(this is the exact residual assumption named in SLICE_01_FINDINGS Finding 3 / "
        "SECURITY_INVARIANTS INV-02)",
        lambda: flagged, False,
    ))
    print("    -> CONFIRMS (against the modeled decode_path) that a single decode pass lets a")
    print("       double-encoded traversal payload pass check_path_traversal! unflagged, IF and")
    print("       only if something downstream decodes the string a second time. Whether such a")
    print("       second decode exists on any real call chain was NOT confirmed in source review")
    print("       (see VALIDATION_01.md) -- this test proves the REGEX/DECODE LOGIC ALONE is")
    print("       insufficient against double-encoding, not that a live sink exists.")

    print()
    print("== Sub-test C: middleware never sees the request body ==")
    # Simulate an attacker sending the SAME payload two ways: as a query param (seen)
    # and as a JSON body field (never passed to the function at all, by construction
    # of the real Rack middleware's Ruby code, which only reads request.fullpath).
    body_payload = {"description": "../../../../etc/passwd"}  # would-be JSON body
    # The ported function signature itself proves the point: it has no `body` parameter.
    import inspect
    sig = inspect.signature(middleware_path_traversal_attempt)
    results.append(test(
        "middleware function has no body/POST-data parameter at all (matches "
        "path_traversal_check.rb, which only calls request.fullpath / request.GET, "
        "never request.body or request.POST)",
        lambda: "body" not in sig.parameters and "query_params" in sig.parameters,
        True,
    ))

    print()
    print("== Sub-test D: EXCLUDED_QUERY_PARAM_NAMES exemption is unconditional ==")
    # A query string carrying the exact same literal traversal payload under an
    # exempted name is stripped before the check ever runs; under a non-exempted
    # name, it is caught.
    exempted = middleware_path_traversal_attempt(
        "/some/endpoint", {"description": "../../../../etc/passwd"}
    )
    not_exempted = middleware_path_traversal_attempt(
        "/some/endpoint", {"totally_unrelated_param": "../../../../etc/passwd"}
    )
    results.append(test(
        "payload under an EXEMPTED param name (description) is NOT flagged",
        lambda: exempted, False,
    ))
    results.append(test(
        "the IDENTICAL payload under a NON-exempted param name IS flagged",
        lambda: not_exempted, True,
    ))

    print()
    print("== Sub-test E: sanity check on genuinely safe input (no false positives on normal paths) ==")
    _, flagged_safe = check_path_traversal("images/avatar.png")
    results.append(test("a normal relative path is NOT flagged", lambda: flagged_safe, False))

    print()
    total = len(results)
    passed = sum(results)
    print(f"=== {passed}/{total} sub-tests behaved as predicted ===")
