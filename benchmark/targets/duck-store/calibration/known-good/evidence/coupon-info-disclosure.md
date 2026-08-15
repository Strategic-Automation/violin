## Evidence: coupon-info-disclosure

### Request
GET /api/v1/orders/coupons HTTP/1.1
Host: duck-store.escape.tech

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"CouponList":[{"code":"FREE100","discount":100}]}

### Analysis
The unauthenticated coupons route returned the full CouponList, confirming information disclosure.
