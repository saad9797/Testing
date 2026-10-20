# Endpoint Inventory — abercrombie.com (Phase 2, pass 1)

## Legacy REST API (from constants.js — base `/api/`)

| Endpoint | Likely function |
|---|---|
| `/api/ecomm/a-wd/session` | Session mgmt |
| `/api/ecomm/a-wd/user` | User profile |
| `/api/ecomm/a-wd/user/exists` | Email/username existence check — **enumeration surface** (excluded class per policy: "rate-limiting/bruteforce/enumeration on non-auth endpoints" — informational at best, don't chase) |
| `/api/ecomm/a-wd/user/remembered` | "Remember me" state |
| `/api/ecomm/a-wd/session/forgot/send` | Password-reset trigger |
| `/api/ecomm/a-wd/session/preferences` (+`/options`) | Account preferences |
| `/api/bags/v3/a-wd/cart/items/list` | Cart contents |
| `/api/payments/v3/a-wd` | Payments |
| `/api/payments/cards/a-wd/v1` | **Saved payment cards** — high sensitivity, IDOR-worth-checking once authenticated |
| `/api/history/a-wd` | **Order history** — high-value IDOR target |
| `/api/anfloyalty/a-wd/user/loyalty/` | **Loyalty points balance** — high-value logic target |
| `/api/cardservice/a-wd` | Gift-card service? (name suggests card/gift-card, needs confirmation) |
| `/api/marketing/a-wd/subscription` | Email subscription |
| `/api/search`, `/api/search/a-wd`, `/api/search/v3/a-wd` | **Three search API versions coexist** — parity-gap candidate (does v1-style `/api/search` enforce the same input handling as v3?) |
| `/api/shipping/pickup/remotelocations`, `/api/eddservice/find{EDD,ESD,CourierAvailability}` | Store/shipping logistics, low sensitivity |
| `/api/gsmap/`, `/api/is/image/imageset/` | Store locator map, image service — low sensitivity |

## GraphQL BFF (`/api/bff/customer`, `/api/supergraph`) — persisted queries, `operationName` + `sha256Hash`

Full operation catalog saved in `recon/customer.js` and `recon/checkoutMFE.js` (grepped, not reproduced in full here — 100+ operations). Highest-value subset:

**Account / auth / orders (customer.js):**
`ORDER_DETAILS_QUERY`, `ASOS_ORDER_DETAILS_QUERY`, `ASOS_LOOKUP_PAGE_QUERY`, `RESEND_ORDER_CONFIRMATION_QUERY`, `ORDERHELP_FORM_QUERY`, `ORDERHELP_SELFSERVICE_PAGE_QUERY`, `CUSTOMER_SELF_SERVICE_QUERY`, `CUSTOMER_IDENTITY_TOKEN_QUERY`, `SESSION_CONTEXT_QUERY`, `REWARDS_DATA_QUERY`, `LOYALTY_POINTS_DATA_QUERY`, `CREATE_USER_OTP_DIALOG_QUERY`, `CREATE_USER_WITH_OTP_MUTATION`, `RESEND_OTP_FOR_USER_CREATION_MUTATION`, `CHANGE_PASSWORD_FORM_QUERY`, `LOGOUT_MUTATION`.

**Cart / checkout (checkoutMFE.js):**
`SHOPPINGBAG_DATA_QUERY`, `SUBMIT_BAG_MUTATION`, `ADDRESS_UPDATE_MUTATION`, `PROMOTION_UPDATE_MUTATION`/`_DELETE_MUTATION` (promo — excluded class, skip), `CHECKOUTPAGE_DATA_QUERY`, `DELIVERY_OPTION_TAB_UPDATE_MUTATION`, `PAYMENT_STATUS_QUERY`, `ORDER_SUBMIT_MUTATION`, `OIS_START_NEW_SESSION_MUTATION`, `REMOVE_REPUDIATED_MUTATION`, `KLARNA_SESSION_QUERY` (BNPL provider), `ORDERCONFIRMATIONPAGE_DATA_QUERY`, `SAVEFORLATER_DATA_QUERY`, `MYLIST_*`, `GIFTCARDPAGE_DATA_QUERY`, `GWP_BAG_MUTATION` (gift-with-purchase).

## Immediate hypotheses queued (see notes/hypotheses.md for full log)

1. `ORDER_DETAILS_QUERY` / `ASOS_ORDER_DETAILS_QUERY` — does the order identifier come from the session alone, or is an order ID/number accepted as a client-supplied GraphQL variable? If the latter, test cross-account access with two synthetic accounts (authenticated phase).
2. `ASOS_LOOKUP_PAGE_QUERY` (guest order lookup) — what proves ownership (order # + zip? order # + email?) — weak-proof guest lookup is a classic e-commerce IDOR pattern.
3. `/api/payments/cards/a-wd/v1` and `/api/history/a-wd` — same own-vs-other-object question via legacy REST instead of GraphQL.
4. Three coexisting `/api/search*` versions — check for validation/authz parity gaps between them.
5. `RESEND_ORDER_CONFIRMATION_QUERY` — if it accepts an arbitrary order ID and re-sends to the order's on-file email (not attacker-controlled), impact is mostly "confirm an order ID exists" (low) unless it can be redirected to a different address — needs checking, don't assume high impact.

## Not yet covered

hollisterco.com, corporate.abercrombie.com, anfcorp.com — no JS pulled yet. Remaining abercrombie.com bundles (`home.js`, `productV2.js`, `category.js`, `catalogV2.js`, legacy `global.js`, `landingPages.js`) not yet grepped.
