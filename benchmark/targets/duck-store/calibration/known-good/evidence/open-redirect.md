## Evidence: open-redirect

### Request
GET /?redirect=https://example.test HTTP/1.1
Host: duck-store.escape.tech

### Response
HTTP/1.1 302 Found
Location: https://example.test

### Analysis
The external Location response confirms an open.redirect through the unvalidated redirect parameter.
