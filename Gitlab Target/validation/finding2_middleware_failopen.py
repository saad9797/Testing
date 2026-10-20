#!/usr/bin/env python3
"""
Validation harness for SLICE_01_FINDINGS.md Finding 2 -- the ONE piece of it that
is pure, deterministic control-flow and does not require a live instance or a real
network topology: does lib/gitlab/middleware/multipart.rb#call REJECT a request
when the trusted Workhorse header is absent, or does it silently pass the request
through unchanged (fail-open) to the rest of the Rack/Rails stack, leaving
`params['file']['remote_id']` etc. exactly as the raw client sent them?

This is a direct, faithful port of the actual Ruby control flow read in this
session:

    def call(env)
      encoded_message = env.delete(RACK_ENV_KEY)
      return @app.call(env) if encoded_message.blank?
      message = ::Gitlab::Workhorse.decode_jwt_with_issuer(encoded_message)[0]
      ::Gitlab::Middleware::Multipart::Handler.new(env, message).with_open_files do
        @app.call(env)
      end
    rescue UploadedFile::InvalidPathError, ApolloUploadServer::GraphQLDataBuilder::OutOfBounds => e
      [400, { 'Content-Type' => 'text/plain' }, [e.message]]
    end

This script does NOT and cannot prove whether Rails is ever reachable without
Workhorse in front of it -- that is a deployment/network question, out of scope
for a source-level or pure-logic test, and is reported as UNCONFIRMED in
VALIDATION_01.md regardless of this script's result.
"""


class FakeApp:
    """Stands in for `@app` (the rest of the Rack/Rails stack)."""
    def call(self, env):
        return {"reached_rails": True, "params_seen": dict(env.get("params", {}))}


RACK_ENV_KEY = "HTTP_GITLAB_WORKHORSE_MULTIPART_FIELDS"


def multipart_middleware_call(env: dict, app: FakeApp):
    """Faithful port of Gitlab::Middleware::Multipart#call's control flow."""
    encoded_message = env.pop(RACK_ENV_KEY, None)
    if not encoded_message:  # .blank?
        # THIS is the line in question: no header -> pass through UNCHANGED, not rejected.
        return app.call(env)

    # (JWT verification / Handler#with_open_files path -- not relevant to this test,
    # since we are specifically testing the "header absent" branch.)
    return {"reached_rails_via_verified_jwt_rewrite": True}


def test(label, actual, expected):
    status = "PASS" if actual == expected else "FAIL"
    print(f"[{status}] {label}: expected={expected!r} actual={actual!r}")
    return status == "PASS"


if __name__ == "__main__":
    results = []

    print("== Scenario: a raw multipart POST reaches this middleware WITHOUT the")
    print("   Workhorse-signed header (i.e. WITHOUT Workhorse having processed it) ==")
    app = FakeApp()
    attacker_env = {
        # no RACK_ENV_KEY present at all
        "params": {"file": {"remote_id": "../../../attacker-supplied-value", "name": "evil.txt"}},
    }
    result = multipart_middleware_call(dict(attacker_env), app)

    results.append(test(
        "middleware with NO Workhorse header calls straight through to the Rails app "
        "(fails OPEN), rather than rejecting/dropping the request",
        result.get("reached_rails"), True,
    ))
    results.append(test(
        "the raw, client-supplied 'file.remote_id' value reaches the app UNCHANGED "
        "and unverified when the trusted header is absent",
        result.get("params_seen", {}).get("file", {}).get("remote_id"),
        "../../../attacker-supplied-value",
    ))

    print()
    print("== Control scenario: header IS present (normal, Workhorse-mediated flow) ==")
    normal_env = {RACK_ENV_KEY: "a.valid.jwt", "params": {"file": {"remote_id": "should-not-be-read-here"}}}
    result2 = multipart_middleware_call(dict(normal_env), app)
    results.append(test(
        "middleware with the header present takes the JWT-verification branch instead "
        "(does not fall through to the unchecked path)",
        result2.get("reached_rails_via_verified_jwt_rewrite"), True,
    ))

    print()
    print("CONCLUSION: this CONFIRMS, at the level of this middleware's own control flow")
    print("(ported faithfully from the source read in this session), that the code makes")
    print("NO attempt to reject or flag a request missing the Workhorse header -- the")
    print("guarantee that params['file']['remote_id'] is trustworthy depends ENTIRELY on")
    print("network/deployment topology ensuring this middleware is never reached without")
    print("Workhorse having run first. This script cannot determine whether that topology")
    print("guarantee actually holds for any real deployment -- see VALIDATION_01.md.")

    total = len(results)
    passed = sum(results)
    print()
    print(f"=== {passed}/{total} sub-tests behaved as predicted ===")
