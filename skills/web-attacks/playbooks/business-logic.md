# Business Logic Flaw — Playbook

## Classification
- **OWASP Top 10:** A1 — Broken Access Control (logic variant) / A4 (2017); logic flaws span the OWASP Top 10
- **CWE:** CWE-840 (unpredictable behavior), CWE-841 (authorization logic), CWE-770 (resource allocation)
- **Severity:** Medium / High (often depends on the business impact of the bypassed rule)
- **Scope:** Enforceable-state, workflow, and multi-step flows where the server must be tricked into a state that violates the intended business rule

## Types

| Type | Description | Detection Hint |
|------|-------------|----------------|
| **Mass Assignment / Parameter Override** | Client-supplied extra fields overwrite protected server-side attributes | Sending an unexpected field changes an object's role/price/status |
| **Negative / Out-of-bounds Quantities** | Math on user-controlled quantities underflows, refunds, or inventory corruption | Negative or huge values yield different totals |
| **Coupon / Discount / Price Manipulation** | Reusable, stackable, or negative-value discount codes distort a charge | Applying coupons in a different order/amount changes the total |
| **Workflow / Step Bypass** | Skipping required sequencing (e.g. checkout without default delivery, escalation without approval) | Requests to a later step succeed when an earlier gate was not satisfied |
| **Race Condition** | Time-of-check/time-of-use on a shared resource (e.g. one-time coupon, stock) | Concurrent identical requests both succeed |
| **Cross-account State Reuse** | A transaction item or cart crosses principals (replay another user's state) | Item added by one account is chargeable by another |

## Detection Payloads

### Price / quantity mutation
```http
POST /api/cart/items   {"product_id": 3, "quantity": -1}
POST /api/cart/items   {"product_id": 3, "quantity": 0}
POST /api/cart/items   {"price": 0}
POST /api/cart/items   {"unit_price": 0, "quantity": 5}
```

### Coupon / discount mutation
```http
POST /api/coupons/apply  {"code": "SAVE100"}
POST /api/coupons/apply  {"code": "SAVE100", "stack": true}
POST /api/coupons/apply  {"code": "XXXX", "discount": -1000}
```

### Workflow bypass
```http
POST /api/orders/confirm           # attempt confirm without an address
POST /api/orders/{id}/deliver     # attempt post-payment action before payment
GET  /api/orders/next             # guess another user's in-flight object
```

## Tools

| Tool | Usage |
|------|-------|
| **curl** | Manual multi-step flow probes and field injection |
| **jq** | Compare JSON responses and totals programmatically |
| **ffuf** | Fuzz field/param names (`price`, `qty`, `role`, `status`) |

## Internet Research Queries
- `OWASP business-logic-testing checklist`
- `price manipulation coupon abuse exploit`
- `negative quantity e-commerce exploit`
- `magic mass assignment broken object level authorization`
- `<product> business logic exploit`

## Safe PoC
Goal: **prove the server enforces the intended business rule** — cause a harmless, reversible state violation and capture the response difference.

1. Capture a clean baseline request/response for the flow (a full cart + checkout).
2. Replay it with a single mutated field (e.g. `quantity: -1` or an extra `price: 0`) and compare responses.
3. Where an out-of-scope system would be affected, stop — the rule is unproven without a decisive status/header capture; a non-zero-length response body alone is not decisive proof.

## Evidence to Save
Store under `$ENG_DIR/evidence/exploitation/business-logic/`:
- Original POST body + response (status line via `curl -i`, headers, body)
- Mutated request/response pair, side by side
- The specific business rule violated and why it proves the flaw

## Stop Conditions
- Rule enforcement that would impact a real third party or sensitive data → stop and notify
- Concurrency/race that triggers backend errors repeatedly → pause and document, don't hammer

## Blocked Actions
- **Do NOT** actually transfer funds, place real orders, or damage the store's data
- **Do NOT** enumerate arbitrary user objects beyond the one in scope
- **Do NOT** brute-force coupons/sessions aggressively