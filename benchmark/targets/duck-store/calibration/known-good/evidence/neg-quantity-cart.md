## Evidence: neg-quantity-cart

### Request
PUT /api/v1/cart/items/123 HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"quantity":-1}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"CartItem":{"id":123,"quantity":-1,"cart_total":-25}}

### Analysis
The cart accepted a negative quantity, proving the negative CartItem quantity defect.
