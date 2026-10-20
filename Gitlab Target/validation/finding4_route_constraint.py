#!/usr/bin/env python3
"""
Validation harness for SLICE_01_FINDINGS.md Finding 4
(route filename constraint: %r{[^/]+} on most upload#show routes vs /.+/ on the
appearance-branding route, config/routes/uploads.rb).

Tests two separate questions:
  (1) Does the routing-layer regex difference actually matter, i.e. does the "strict"
      %r{[^/]+} constraint stop a `../`-shaped payload from matching the route at all,
      while the "loose" /.+/ constraint lets it through to the controller?
  (2) Does that routing-layer difference survive an attacker using a URL-encoded slash
      (%2F) instead of a literal slash -- which would let a `../../` payload be
      represented inside a SINGLE route segment (no literal '/' char) and therefore
      satisfy BOTH the strict and the loose constraint equally, making the routing-layer
      distinction irrelevant to actual exploitability?

Question (2) depends on whether Rails/Rack decodes %2F into a literal '/' BEFORE or
AFTER the router applies the segment regex constraint. This is a real Rails/Rack-version
-dependent behavior that could NOT be resolved from static source reading in this
session (Rack/ActionDispatch source was not in the sparse checkout, and no live
instance was available). Both branches are modeled and reported explicitly as
alternatives -- this script proves what happens in EACH branch, not which branch is
true for the real, deployed Rack/Rails version. See VALIDATION_01.md for the
resulting UNCONFIRMED classification and what a live test would need to check.
"""

import re
import urllib.parse

# Exact regexes as read from config/routes/uploads.rb
STRICT_FILENAME_CONSTRAINT = re.compile(r"^[^/]+$")   # used on 5 of 6 `uploads#show` routes
LOOSE_FILENAME_CONSTRAINT = re.compile(r"^.+$", re.DOTALL)  # used ONLY on the appearance/branding route


def rails_route_would_match(segment: str, constraint: re.Pattern) -> bool:
    """Models Rails' route-segment constraint check: does this string, taken as the
    :filename dynamic segment, satisfy the named regex constraint?"""
    return constraint.match(segment) is not None


def test(label, actual, expected):
    status = "PASS" if actual == expected else "FAIL"
    print(f"[{status}] {label}: expected={expected!r} actual={actual!r}")
    return status == "PASS"


if __name__ == "__main__":
    results = []

    print("== Part 1: literal traversal payload, unencoded ==")
    literal_payload = "../../../../etc/passwd"
    strict_match = rails_route_would_match(literal_payload, STRICT_FILENAME_CONSTRAINT)
    loose_match = rails_route_would_match(literal_payload, LOOSE_FILENAME_CONSTRAINT)
    results.append(test(
        "STRICT constraint ([^/]+) rejects a literal ../../ payload at the routing layer",
        strict_match, False,
    ))
    results.append(test(
        "LOOSE constraint (.+) accepts the identical literal ../../ payload at the routing layer",
        loose_match, True,
    ))
    print("    -> CONFIRMS the routing-layer inconsistency is real: for a literal,")
    print("       unencoded traversal payload, the appearance/branding route reaches the")
    print("       controller while every sibling route 404s before the controller runs.")

    print()
    print("== Part 2: does URL-encoding the slash (%2F) equalize the two constraints? ==")
    encoded_payload = literal_payload.replace("/", "%2F")
    print(f"    encoded segment as it would appear on the wire: {encoded_payload}")

    # Branch A: Rack/Rails decodes %2F to '/' BEFORE the router applies the segment
    # constraint (i.e. the constraint sees the fully-decoded string).
    decoded_first = urllib.parse.unquote(encoded_payload)
    strict_match_decoded_first = rails_route_would_match(decoded_first, STRICT_FILENAME_CONSTRAINT)
    print(f"    Branch A (decode-before-constraint): decoded='{decoded_first}' "
          f"strict_match={strict_match_decoded_first}")
    results.append(test(
        "Branch A: if Rack decodes %2F before constraint matching, STRICT still rejects it "
        "(no difference from Part 1 -- the encoding doesn't help the attacker here)",
        strict_match_decoded_first, False,
    ))

    # Branch B: Rails matches the constraint against the RAW, still-percent-encoded
    # segment (i.e. '%2F' is just three literal characters '%','2','F' to the regex,
    # containing no literal '/' at all), and decoding happens LATER in application code
    # (e.g. Gitlab::Utils.decode_path inside check_path_traversal!, or Rack itself
    # when it builds `params`).
    strict_match_raw = rails_route_would_match(encoded_payload, STRICT_FILENAME_CONSTRAINT)
    print(f"    Branch B (constraint-sees-raw-encoded): raw='{encoded_payload}' "
          f"strict_match={strict_match_raw}")
    results.append(test(
        "Branch B: if Rails matches the constraint against the RAW %2F-encoded segment, "
        "STRICT constraint ([^/]+) is satisfied (no literal '/' present) -- meaning the "
        "'stricter' route provides ZERO additional protection over the loose route once "
        "the payload is delivered with an encoded slash, and check_path_traversal!'s "
        "decode-then-regex-check becomes the ONLY real defense for BOTH route families",
        strict_match_raw, True,
    ))

    print()
    print("== Conclusion printed for the record (not a pass/fail assertion) ==")
    print("If Branch B is what the real, deployed Rack/ActionDispatch version does (which")
    print("this script cannot determine without a live instance), then SLICE_01 Finding 4's")
    print("routing-layer distinction is REAL but LARGELY COSMETIC: an attacker who simply")
    print("encodes the slash defeats the 'strict' constraint just as easily as the 'loose'")
    print("one, and check_path_traversal! (which decodes first) is doing 100% of the actual")
    print("work on every route in this table, not just the appearance route. This would")
    print("downgrade Finding 4's practical severity, though not its status as a real,")
    print("directly-read routing inconsistency.")

    total = len(results)
    passed = sum(results)
    print()
    print(f"=== {passed}/{total} sub-tests behaved as predicted ===")
