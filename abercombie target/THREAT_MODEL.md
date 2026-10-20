# Threat Model — Abercrombie & Fitch web assets

## Phase 1 note: disclosed-report mining came up empty

Hacktivity for this program (13 resolved reports, $750–$4,000 range, most within the last 3 weeks — confirms the program is genuinely active and currently paying) shows bounty amounts and reporter handles only; **titles/descriptions are all private**, no CWE/class data disclosed. A companion program `hackerone.com/abercrombie_fitch` is a separate no-bounty VDP, also not useful for class-mining. No public writeups found via search. Threat model below is built from live-observed architecture + generic high-value e-commerce logic classes, not from this program's own disclosed history.

## Confirmed tech stack (from live recon, unauthenticated)

- Backend: IBM/HCL WebSphere-Commerce-lineage (`catalogId=10901`, `storeId=11203`, `langId=-1` params — signature naming)
- **GraphQL BFF layer**: `/api/bff/customer`, `/api/bff/catalog`, `/api/supergraph` (Apollo Federation-style naming)
- Client uses **persisted queries**: `operationName` + `sha256Hash`, e.g. `SIGN_IN_BUTTON_QUERY`, `SIGN_IN_TOASTER_QUERY`, `CREATE_USER_OTP_DIALOG_QUERY`
- Personalization/experimentation: Adobe Target (`tt.omtrdc.net`), LaunchDarkly feature flags
- **Fraud/bot detection is active**: Signifyd (`dp.signifyd.com/fp-web` — e-commerce fraud-scoring), a `_fs-ch-<id>/check-detection` + `/acd` challenge endpoint (bot-detection style), FullStory session replay, Dynatrace RUM
- Auth appears to include an OTP/passwordless dialog (`CREATE_USER_OTP_DIALOG_QUERY`) alongside standard sign-in

## Crown jewels

1. Customer PII (name, address, email, phone, DOB if loyalty-linked)
2. Order history / order detail (items, totals, payment method last-4, shipping address)
3. Loyalty/rewards points balance and redemption
4. Gift card balance/codes
5. Saved payment methods (tokenized, but the token-reference itself is sensitive)
6. Account credentials / session (auth bypass, ATO)
7. Corporate/admin functionality on `corporate.abercrombie.com` / `anfcorp.com` (out of core retail flow, but in scope — likely CMS/vendor/investor-relations content, not transactional)

## Invariants to test (living list)

Status key: SUSPECTED (not yet tested) / CONFIRMED / DISPROVEN

- [SUSPECTED] A customer can only read/modify their own orders, addresses, profile, payment methods, and loyalty balance via `/api/bff/customer`.
- [SUSPECTED] Object identifiers (order ID, address ID, account ID) used in BFF GraphQL `variables` are re-validated server-side against the authenticated session, not trusted at face value.
- [SUSPECTED] Persisted-query enforcement is strict: server validates that `operationName` matches the registered query text for a given `sha256Hash` (i.e. you can't send a different `operationName` against a hash registered for another query, or invoke an unlisted/deprecated persisted query hash still present in an old JS bundle).
- [SUSPECTED] Cart line-item price/quantity/totals are recomputed server-side at checkout, not trusted from client state.
- [SUSPECTED] Order state machine can't be skipped/replayed (e.g. can't reach "confirmed" without a completed payment step; can't re-trigger a already-consumed one-time action like a password-reset or OTP token).
- [SUSPECTED] Session/auth token is bound to the account that created it; no fixation/reuse across accounts.
- [SUSPECTED] The OTP/passwordless sign-in flow rate-limits and properly invalidates codes after use/expiry (classic OTP logic bugs: no expiry check, reusable code, no bind to the requesting session).
- [SUSPECTED] Loyalty/rewards point adjustments and gift-card balance changes are server-authoritative, not client-supplied.
- [SUSPECTED] Older/deprecated API versions or the mobile-app-facing BFF variant (if same backend, if in scope) enforce the same authorization checks as the current web client.

## Attacker models in play

1. **Remote unauthenticated** — current phase. Can view public storefront, product/search pages, sign-up/sign-in flow, and any endpoint reachable without a session.
2. **Remote authenticated, low-priv customer (self)** — next phase, needs Burp + login. Tests own-account CRUD, checkout logic, OTP/session handling.
3. **One customer vs. another customer's data** — the highest-value class (BOLA/IDOR). Requires **two synthetic accounts you control** per the escalation ladder's hard stop — never a real customer's data. Will need a second self-registered wearehackerone-alias test account when we get there.

## Slice priority (for Phase 3, once authenticated)

Ranked by crown-jewel proximity and typical logic-flaw density on retail platforms, since disclosed-report evidence wasn't available to re-rank this list:

1. Access control / IDOR across the BFF (own vs. other synthetic account) — highest value, matches "object authorized vs. object acted upon" frame
2. Auth + session + OTP/password-reset logic
3. Account/profile/address-book CRUD
4. Cart & checkout logic (server-side recompute, step-skipping) — stop before any real charge
5. Order state machine (status transitions, replay)
6. Loyalty/rewards & gift-card logic
7. Review/search input handling (lower priority — commodity XSS territory, likely already heavily duplicated)
8. API-version / mobile-API parity gaps (only if mobile BFF endpoints are reachable and in scope)

## Next: Phase 2 — JS/endpoint inventory (unauthenticated, in progress)
