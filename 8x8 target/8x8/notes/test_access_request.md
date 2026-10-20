# Draft: request test access from the 8x8 program (send via HackerOne)

How to send: on https://hackerone.com/8x8-bounty, use "Submit report" but choose the
program's contact / "Ask a question" path if available, OR submit a low-severity
informational report titled as below. Keep it short and professional. Send as saad101.

---

Subject: Request for test access to eligible in-scope applications

Hi 8x8 team,

I'm a researcher on your program (saad101) and would like to test the bounty-eligible
applications that require authentication — specifically 8x8 Work (work.8x8.com),
user-profile.8x8.com, and the Virtual Contact Center (vcc-*.8x8.com).

The policy notes test credentials aren't provided by default, and 8x8 Express
self-signup has been discontinued, so I don't currently have a legitimate way to
reach the authenticated surface of these eligible assets.

Would the team be willing to either (a) provision a test account, or (b) sanction a
trial account I create using my HackerOne alias (saad101@wearehackerone.com)? I'll
follow all program rules — X-HackerOne header on every request, low request volume,
and only interacting with accounts I own.

Thanks for considering, and for running such a responsive program.

— saad101
---

## Notes
- Expect a possible "no" — the policy says test creds aren't provided "at this time."
  Asking is still the correct, in-scope move and costs nothing.
- If they say yes: we test IDOR (enumerable IDs only — UUID/AccountId/subAccountId are
  OUT), business logic, stored XSS in profile/chat fields, and access control between
  two accounts you own.
- If they say no: the realistic options are an 8x8 Work sales trial, or pivoting to a
  program that actually offers self-signup test accounts.
