# Hypotheses log

Format: hypothesis | evidence | test | expected | observed | conclusion

## H1 — Order details BOLA/IDOR
- **Hypothesis**: `ORDER_DETAILS_QUERY` (and/or `ASOS_ORDER_DETAILS_QUERY`) resolves an order by a client-supplied order ID/number in GraphQL `variables` rather than deriving it solely from the authenticated session, allowing account A to read account B's order.
- **Evidence so far**: operation exists in customer.js bundle. Captured live authenticated traffic on the real order-history page (logged in as the test account) — the query never fires because **the test account has zero orders** (empty state renders without calling it).
- **Test**: BLOCKED. Getting a real order into the account requires an actual purchase/payment, which is a hard stop (never complete a real transaction). Cannot observe the real variable shape this way.
- **Conclusion**: BLOCKED — not disproven, just untestable without crossing a hard stop. Revisit only if a way to get legitimate order data appears (e.g. a free/zero-cost order path, or a sandbox/test-mode checkout if one exists — not yet checked).

## H2 — Guest order lookup weak proof-of-ownership
- **Hypothesis**: guest order lookup (`ASOS_LOOKUP_PAGE_QUERY`, UI at `/shop/wd/help/lookup-order`) authorizes access to an order via a single weak factor rather than something only the real customer would know.
- **Evidence so far**: **form requires both Order Number AND Email Address (from order)** — two-factor proof of ownership, not a single weak factor. This is the secure pattern, not a weak one; H2 as originally framed is largely disproven.
- **Refined sub-hypothesis (not yet tested)**: does the server return a different error/timing for "order number doesn't exist" vs. "order number exists but email doesn't match"? A differential here would let an attacker enumerate valid order numbers without knowing the associated email — but note this sits close to the policy's excluded "enumeration on non-auth endpoints" class, so any test here should be a single, minimal comparison (one bad order number vs. one valid-shape-but-wrong-email), never a bruteforce/volume test.
- **Conclusion**: original framing DISPROVEN (two-factor, not weak). Refined differential-error sub-hypothesis still PENDING, low priority given scope ambiguity.

## H3 — Payment cards / order history legacy REST IDOR
- **Hypothesis**: `/api/payments/cards/a-wd/v1` and `/api/history/a-wd` scope strictly to the session's own account.
- **Test**: authenticated phase, two synthetic accounts, same object-substitution pattern as H1.
- **Observed**: PENDING.
- **Conclusion**: PENDING.

## H4 — Search API version parity gap
- **Hypothesis**: `/api/search` (legacy) does not enforce the same input validation/authz as `/api/search/v3/a-wd`.
- **Test**: unauthenticated — compare both endpoints' behavior on the same query, check for differences in error handling, injected characters, response shape.
- **Observed**: PENDING.
- **Conclusion**: PENDING.

## H5 — Associate discount MFA flow
- **Hypothesis**: unclear whether this is genuinely in-scope-and-distinct from "promotional/discount code abuse" (excluded class) or whether it would be judged a duplicate/excluded exclusion.
- **Status**: PARKED — needs a judgment call before spending any time here. Flagged to user, not pursued.

## H6 — anfcorp.com / vendor portal pre-auth exposure
- **Hypothesis**: `anfcorp.com` redirects to `vendorportal.anfcorp.com` (WordPress-based B2B vendor portal, newest asset in scope — added 2024-07-15 per scope CSV, likely less hunted). Checked for common pre-auth exposure: open REST API, readme/version disclosure, xmlrpc.php, missing security headers on login page.
- **Observed**: REST API returns `401 rest_not_logged_in` (properly gated, unlike corporate.abercrombie.com's open wp-json). `readme.html` blocked with 403 at the nginx layer. Login page has X-Frame-Options, CSP `frame-ancestors 'self'`, Referrer-Policy set, and HttpOnly+Secure cookies. This is a materially better-hardened WordPress deployment than the corporate site.
- **Conclusion**: DISPROVEN for the easy pre-auth wins checked so far. Also structurally blocked for anything past the login wall: this is a vendor/supplier B2B portal, not self-registerable like the retail sites — we have no legitimate credentials for it and can't get any without being an actual approved vendor, so authenticated testing here isn't available to us at all. Closing this thread unless a pre-auth login-bypass surfaces (none found).

## H7–H10 — BFF access-control candidates (static-derived 2026-09-27)
New IDOR/BOLA surface found by mining `recon/customer.js` operation signatures. Full PoCs + methodology in `recon/findings/idor-candidates-bff.md`.
- **H7 (HIGH)** Address-book IDOR: `UpdateAddress/RemoveAddress/SetDefaultAddress($id: ID!)` all take a bare client ID; `getAllAddresses` leaks the IDs. `SetDefaultAddress` = default-shipping repoint (fraud/PII). **Testable now, no order needed — do first.** Two synthetic accounts.
- **H8 (HIGH)** `GenerateGiftReceipt($orderId: String!, $email: String)` — client orderId (typed String!, looser than sibling ID!) + client-chosen recipient email = order-content exfil to attacker inbox if orderId not session-scoped. Gated by order-seeding blocker.
- **H9 (MED-HIGH)** `ASOS_ORDER_DETAILS_QUERY($orderId, $postalCode)` — postalCode may be the *only* ownership factor (low entropy). Single correct-value cross-account request = clean proof; no brute (excluded class).
- **H10 (MED)** `UpdateOrderPayment(input: UpdatePaymentInput!)` — capture live input shape; check for unscoped orderId. Lower priority.

## Disproven / ruled out this pass
- H2 (original framing): guest order lookup uses two-factor proof, not weak single-factor.
- H6: anfcorp.com vendor portal pre-auth surface — properly hardened, no easy exposure found; authenticated testing structurally unavailable (no vendor credentials, not self-registerable).
