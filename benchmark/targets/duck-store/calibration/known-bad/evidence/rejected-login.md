POST /api/v1/auth/login HTTP/1.1
{"username":"admin","password":"admin"}
HTTP/1.1 403 Forbidden
Content-Length: 200
{"error":"invalid credentials"}
