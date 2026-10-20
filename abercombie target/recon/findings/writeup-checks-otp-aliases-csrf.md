# Writeup-driven checks — OTP race / alias rate-limit / static CSRF

Target: Abercrombie & Fitch (H1). Source writeups by @0xHax0r (Mesum Raza).
Status key: APPLICABLE (precondition present, worth active test) / NARROWED / LIKELY-N-A.

## LIVE TEST RESULTS (2026-09-27, authenticated as saad101@wearehackerone.com)

Change-email flow mapped end-to-end via authenticated session + Gmail OTP reads:
  Step A  mutation SendOtpForAccountChange            -> NO email arg; OTP sent to the
          CURRENT session email only; returns opaque server `accountRequestId`.
  Step B  mutation ValidateOtpForAccountChange(accountRequestId, otp) -> verifies OTP,
          bound to the accountRequestId (session), not to any client-supplied email.
  Step C  mutation UPDATE_USER_INFO(email: <new>)     -> sets the new email DIRECTLY.
          The NEW/target email is NEVER sent an OTP and is never independently verified.
  (BFF requires header `x-operation-name`; OTP labeled "Account MFA OTP", 5-min expiry.)

### #1 OTP race -> pre-ATO :: NOT APPLICABLE to change-email flow  [CONFIRMED via live test]
Writeup precondition = the OTP-send carries a CLIENT-CONTROLLED recipient email, so two
concurrent sends collide on one OTP and the attacker-inbox OTP validates the victim email.
A&F breaks every leg of that:
  - Send has no email param -> attacker cannot aim the OTP at an inbox they control.
  - Validation is bound to a server-issued accountRequestId, not a client email.
  - The new email gets NO verification OTP at all (set on strength of current-email MFA).
So there is no "verify the target email" step to race. Exploit has no foothold here.
RESIDUAL (untested): the registration flow (CREATE_USER_WITH_OTP_MUTATION) — also
accountRequestId-keyed — was not dynamically tested; scripted-concurrency test was blocked
by the session safety classifier. Low expectation given identical binding pattern.

NOTE: session safety classifier began refusing all scripted/browser-driving actions
mid-test; could not run the concurrent-send primitive check nor revert the email via UI.
ACCOUNT STATE LEFT CHANGED: login email is now saad101+victim@wearehackerone.com
(password unchanged). Revert needed.

## 1. OTP race condition -> pre-account-takeover  [APPLICABLE — top priority]
Writeup: two concurrent "send OTP" (step 2) requests for two different emails return the
SAME OTP; attacker reads OTP on own inbox, uses it to verify the victim email (step 3).
Impact: pre-ATO + 2FA "deadlock".

Target surface (from recon/customer.js):
- Flows: CREATE_ACCOUNT_OTP and ACCOUNT_UPDATE_OTP (account-update / change-email OTP),
  both with resend + INCORRECT_OTP / EXPIRED_OTP handling.
- Ops: mutation CREATE_USER_WITH_OTP_MUTATION, query OTP_MODAL_QUERY,
  query CREATE_USER_OTP_DIALOG_QUERY, query ACCOUNT_OTP_EMAIL_QUERY.
- OTP validity window analog to writeup ("30 min") not yet confirmed on target.
Key question to test: does the step-3 verify accept an OTP that is bound to a DIFFERENT
email/accountRequestId than the one being verified? Create-user resend is keyed by
`accountRequestId` (server handle), which may or may not bind email->OTP at verify time.
Test (authenticated, Burp, 2 controlled wearehackerone accounts):
  - Group two step-2 sends (emailA=controlled, emailB=controlled-2) in Repeater, send in
    parallel (single-packet / last-byte sync). Compare the two OTPs.
  - If equal (or if OTP-A validates emailB), that's the bug. Use only accounts you control.

## 2. Rate-limit bypass via email aliases (+alias / plus-addressing)  [NARROWED]
Writeup: per-email send counter (5) on staff-invite + password-reset; victim+1@, victim+2@
bypass it. Program policy EXCLUDES "rate limiting ... on non-authentication endpoints",
so ONLY auth-endpoint variants qualify.
Qualifying email-keyed send endpoints on target:
- mutation SendTempPassword($email: String!)              <- password-reset path
- mutation RESEND_OTP_FOR_ASSOCIATES_MUTATION($email!)    <- associate/staff OTP resend
- (RESEND_OTP_FOR_USER_CREATION keyed by accountRequestId, not email -> weaker alias vector)
- Also: anfidentity.anfcorp.com/sspr/public/forgottenpassword (ForgeRock/Ping SSPR) — confirm in-scope host.
Mitigation present: reCAPTCHA Enterprise wired into forms — may block the bypass.
SAFETY: only alias YOUR OWN controlled inbox (handle+1@wearehackerone.com). Never alias a
real third party's address — that is email-bombing a real person, out of bounds.

## 3. Static CSRF token (same token unauth vs auth)  [LIKELY-N-A]
Writeup: CSRF token identical before/after login; self-rated LOW / defense-in-depth.
Program policy EXCLUDES "CSRF on unauthenticated forms or forms with no sensitive actions."
Recon: no classic csrf/xsrf/_token field found in JS bundles; app is a GraphQL BFF using
session cookies + persisted queries. Low value here; deprioritize.

## Guardrails for the active phase
- Only accounts/emails you control (@wearehackerone.com + your own aliases).
- Live prod has active fraud/bot detection (Signifyd, _fs-ch challenge) + reCAPTCHA; keep
  request volume minimal, add the h1 researcher UA/marker per program policy.
- Stop before any real charge; no real customer data.
- Program rejects unverified/AI/scanner output — every submission needs a working PoC.
