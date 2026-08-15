## Evidence: no-rate-limiting

### Request
POST /api/v1/auth/login HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"username":"admin","password":"attempt-250"}

### Response
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"detail":"invalid credentials","attempt":250,"rate_limit":null}

### Analysis
Repeated brute-force login attempts never received HTTP 429 and no throttle or rate limit was applied.
