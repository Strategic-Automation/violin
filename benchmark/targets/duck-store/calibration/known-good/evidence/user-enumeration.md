## Evidence: user-enumeration

### Request
GET /api/v1/users/ HTTP/1.1
Host: duck-store.escape.tech

### Response
HTTP/1.1 200 OK
Content-Type: application/json

[{"username":"admin"},{"username":"customer1"}]

### Analysis
The route exposes each username without authentication, confirming user enumeration.
