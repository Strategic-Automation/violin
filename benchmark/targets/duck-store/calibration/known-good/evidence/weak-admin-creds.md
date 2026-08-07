## Evidence: weak-admin-creds — Default Admin Credentials

### Request
POST /api/v1/auth/login HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"username":"admin","password":"password"}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"token":"eyJhbGciOiJIUzI1NiJ9...","user":{"username":"admin","role":"admin"}}

### Analysis
DefaultCredentials confirmed: the admin account uses weak credentials (admin/password).
