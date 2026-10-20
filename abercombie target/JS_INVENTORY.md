# JS Inventory — abercrombie.com (Phase 2, pass 1)

Architecture: micro-frontend (MFE), each area independently built/versioned and loaded via its own hashed static path (Webpack Module Federation-style: `quickviewStub.js` is literally under a `federation/` path). Bundles pulled and saved under `recon/` for offline grep (not re-fetched repeatedly, to keep request volume low per the "no stated rate limit → be conservative" note in scope.md).

| Bundle | Path | Size | Relevance |
|---|---|---|---|
| constants.js | `/shop/ConstantsJSBase?storeId=11203&catalogId=10901&langId=-1` | 253KB | **Config/route map** — full legacy REST API base paths |
| customer.js | `/static/customer/2ee0d7d0/scripts/customer.js` | 1.3MB | Account/auth/order-help GraphQL operations (highest value) |
| checkoutMFE.js | `/static/checkout/3c64befd/scripts/checkoutMFE.js` | 2.1MB | Cart/checkout/payment GraphQL operations |
| catalog-global.js | `/static/catalog/2f8ad7c2/scripts/global.js` | 776KB | Catalog/search, references `/api/identity` |
| quickviewStub.js | `/static/product/466de85d/federation/quickviewStub.js` | 16KB | Module-federation stub — confirms MFE architecture; small, low yield itself |
| globalV2.js | `/anf/91e6adba/js/globalV2.js` | 485KB | Legacy global bundle (pre-MFE-migration code, still shipped) |

Not yet pulled (next pass): `home.js`, `productV2.js`, `category.js`, `catalogV2.js`, `legacy/desktop/global.js`, `landingPages.js`, and the equivalent bundles on **hollisterco.com** (same architecture per program's own note that A&F and Hollister share underlying code — useful to diff for parity gaps), plus `corporate.abercrombie.com` and `anfcorp.com` (likely a different, CMS-style stack — not yet fingerprinted).

## Naming curiosities worth a closer look

- `ASOS_ORDER_DETAILS_QUERY`, `ASOS_LOOKUP_PAGE_QUERY` — "ASOS" is an unrelated brand name appearing inside A&F's own operation names. Likely a shared/white-labeled guest-order-lookup component from a common commerce-platform vendor, kept under its original internal codename. Worth checking whether this code path behaves differently (weaker auth?) than the equivalent authenticated `ORDER_DETAILS_QUERY`.
- `REMOVE_REPUDIATED_MUTATION` — implies explicit handling of disputed/failed payment line items; a named edge case in the order state machine, exactly the kind of "buried state transition" worth probing later (authenticated phase).
- `VALIDATE_MFA_CODE_FOR_ASSOCIATES_MUTATION` / `RESEND_OTP_FOR_ASSOCIATES_MUTATION` / `ASSOCIATE_DISCOUNT_*` — an **employee ("associate") discount verification flow** ships in the same customer-facing bundle. Flagged as **caution, not a green light**: the program excludes "promotional/discount code abuse," and this may be judged to fall under that exclusion even though it's a distinct MFA mechanism rather than a promo code. Do not pursue without weighing that ambiguity first.
