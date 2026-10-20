# BFF access-control (BOLA/IDOR) candidates — static-derived, PoC-ready

Target: Abercrombie & Fitch (H1 `abercrombie_fitch_bbp`). Slice: **access control across `/api/bff/customer`** (top-ranked slice in THREAT_MODEL.md).
Derived purely from static analysis of `recon/customer.js`. All require the authenticated phase (session cookie) + **two synthetic wearehackerone accounts you control** to prove cross-account access. None require touching real customer data.

BFF call convention (from prior live mapping): POST `/api/bff/customer`, session cookie, header `x-operation-name: <OperationName>`, persisted-query `sha256Hash` + `variables`. Add the h1 researcher UA marker per policy. Keep every test to single, hand-sent requests — no scripted volume (Signifyd + reCAPTCHA + `_fs-ch` challenge are live).

---

## C1 — Address-book IDOR (write/delete/default-repoint)  [HIGH — top priority]

Operations, all keyed on a bare client-supplied `ID!`:
- `mutation UpdateAddress($id: ID!, $address: AddressInput!)`
- `mutation RemoveAddress($id: ID!)`
- `mutation SetDefaultAddress($id: ID!)`
- listing: `query GetAddressPageData { getAllAddresses { defaultId, addresses { id ... } } }`

**Invariant under test:** the server re-validates that `$id` belongs to the session's account before mutating it (THREAT_MODEL invariant #2).

**Why it's a candidate:** three separate mutations accept a raw object ID with no accompanying ownership factor. `SetDefaultAddress` is the highest-impact leg — repointing a victim's *default shipping address* is a fraud/PII vector (their next order or profile data flows to attacker-chosen address), and it's a pure state change, cleanly reversible in a PoC.

**PoC (two accounts A=attacker, B=victim, both yours):**
1. As B, call `GetAddressPageData`, record an address `id` (`idB`). **Note the ID format — sequential int vs opaque UUID decides blast radius:** sequential ⇒ enumerate arbitrary victims; opaque ⇒ still a valid IDOR if the ID leaks (order confirmations, shared links) but not mass-enumerable. Record this verbatim in the report.
2. As A (different session cookie), send `SetDefaultAddress($id: idB)` (and separately `UpdateAddress`/`RemoveAddress` against `idB`).
3. **Expected if secure:** `NOT_FOUND` / authz error. **Bug:** `success: true`, and re-reading B's `GetAddressPageData` shows the change. Screenshot both sessions. Revert immediately.

---

## C2 — `GenerateGiftReceipt` order-data exfil to arbitrary email  [HIGH]

`mutation GenerateGiftReceipt($orderId: String!, $email: String) { generateGiftReceipt(orderId, email) { success receipt } }`

**Two problems in one signature:**
- `orderId` is client-supplied (and typed `String!`, looser than the `ID!` used elsewhere — a consistency smell).
- optional `$email` = server sends the receipt to a **client-chosen** address.

**Invariant:** `orderId` must be scoped to the session's account before a receipt is generated/sent.

**Candidate impact:** if `orderId` isn't session-scoped, an attacker generates a gift receipt for someone else's order (`receipt` field = order-content disclosure) **and** can have it emailed to an attacker inbox via `$email`. Order-content PII disclosure = potentially Critical per this program's max-severity.

**PoC:** as A, call `GenerateGiftReceipt(orderId: <B's order id>, email: <A-controlled wearehackerone alias>)`. Blocked today only by "no order in either account yet" (see H1 blocker below) — resolve the order-seeding problem and this is directly testable with two of your own accounts. Never target a real order.

---

## C3 — `ASOS_ORDER_DETAILS_QUERY` — is postalCode the *only* secret?  [MEDIUM-HIGH]

`query ASOS_ORDER_DETAILS_QUERY($orderId: ID!, $postalCode: String!) { asosOrderDetails(orderId, postalCode) {...} }`

**Tell:** this returns full order-detail items yet requires `postalCode` alongside `orderId`. If it were purely session-scoped, postalCode would be redundant — its presence suggests the resolver may authorize on `orderId`+`postalCode` **instead of** the session. postalCode is low-entropy / frequently known for a targeted victim.

**Invariant:** for an *authenticated* order view, ownership must come from the session, not from a guessable postalCode.

**PoC (two accounts):** as A, request B's `orderId` with B's correct `postalCode`. If it returns B's order, authorization is postalCode-bound, not session-bound → weak second factor. (Do **not** brute postalCodes — that crosses the excluded "enumeration" class and the volume guardrail. One correct-value request with your own second account is the clean, in-scope proof.)

---

## C4 — `UpdateOrderPayment(input: UpdatePaymentInput!)`  [MEDIUM — needs input shape from live]

`mutation UpdateOrderPayment($input: UpdatePaymentInput!) { updateOrderPayment(input) { success updatedOrderStatus } }`

Input type is server-side; client construction resets `{cardNumber, expirationDate, securityCode, cardBrand, ...}`. **Get the exact `input` shape from one live authenticated call** (does it carry an `orderId`?). If it does and it's not session-scoped, an attacker could alter payment on another's order (`updatedOrderStatus` in the response confirms state change). Lower priority until the input is captured live.

---

---

## C5 — Gift-card apply/balance: PIN & captcha optional at the API layer  [HIGH — money vector]

From `checkoutMFE.js` (`/api/bff/checkout`):
- `query CheckGiftCardBalance($cardNumber: String!, $pin: String, $country, $captchaToken: String)`
- `mutation ApplyGiftCard($cardNumber: String!, $pin: String, $country, $captchaToken: String)`

**`$pin` and `$captchaToken` are both optional** (`String`, not `String!`). Static analysis can't tell whether the server enforces them — that's the whole test.

**Invariant:** redeeming/reading a gift card must require the PIN (the shared secret) and a valid captcha; neither can be optional server-side.

**Candidate impact (crown jewel = money):**
- If `ApplyGiftCard` credits a card to your cart **without a valid PIN**, that's direct theft of arbitrary gift-card balances.
- If `CheckGiftCardBalance` returns balance **without PIN and without captcha**, it's a funded-card oracle. Note: pure balance enumeration brushes the excluded "enumeration/rate-limiting on non-auth endpoints" class — but *applying* value without the PIN is theft, squarely in scope. Frame the report around apply-without-PIN, not mass enumeration.

**PoC:** one `CheckGiftCardBalance` with a card you own, `pin` omitted, `captchaToken` omitted. If it returns a real balance, the secret/captcha aren't enforced. Then one `ApplyGiftCard` (your own card, no pin) against your own cart. Never test against a card you don't own.

## C6 — `SendToRegister` client-tamperable `sendToRegisterURL` + arbitrary `email`  [MEDIUM]

`mutation SendToRegister($email: String!, $brand, $oisTrackingId, $skus: [String!]!, $store, $sendToRegisterURL: String!)` (in-store "send cart to register" flow).

`sendToRegisterURL` is server-provided config echoed straight back into the mutation, and `email` is fully client-controlled. If the server **fetches** that URL server-side → SSRF; if it **emails a link** built from it → open-redirect/phishing to an arbitrary recipient. Response returns `statusCode/success/statusMessages`, implying the server acts on it.

**PoC (needs the in-store/kiosk context reachable):** send with `sendToRegisterURL` pointed at a collaborator host you control (e.g. Burp Collaborator) and `email` = your alias; watch for an inbound server-side hit (SSRF) or inspect the delivered email's link (redirect). Confidence medium — depends on whether this flow is reachable in the web session at all.

## C7 — `SubmitOrder` client-supplied `paymentInfo` / price integrity  [MEDIUM — stop before charge]

`mutation SubmitOrder($orderSubmitInput: OrderSubmitInput!, $paymentInfo: PaymentInfoInput!)` + `AddCartItem($shortSku, $quantity: String!)` (quantity typed **String**).

**Invariant:** line prices, totals, and quantities are recomputed server-side; `paymentInfo` can't override amount owed. Test negative/overflow/`"0"` quantity in `AddCartItem`, and any client-supplied amount field in `paymentInfo`. **Hard stop before any real charge** — observe the recomputed total in the pre-submit response, do not click through payment. Lower priority precisely because the safe stopping point is before proof of impact.

---

## Shared blocker to resolve first (gates C2–C4, C7 fully)

Per `notes/hypotheses.md` H1: the test account has **zero orders**, so no real `orderId` exists to substitute, and order-scoped tests (C2/C3/C4) can't run end-to-end. Address-book (C1) does **not** need an order and is testable now — **do C1 first.** For the order-scoped ones, find a legitimate zero-/low-cost order path or a test-mode checkout, or accept them as "reasoned, PoC-blocked" per the program's evidence bar. Do not complete a real charge.

## Loose end (carry-over from OTP writeup — do before more testing)
Test account login email was left as `saad101+victim@wearehackerone.com` (password unchanged). **Revert to the canonical address** via the account UI so later differential/IDOR tests start from a known-clean state.
