# WebSocket Session and Message Authorization

Use this guide only when the target exposes an authorized WebSocket endpoint
and the installed runtime has a guarded client capable of producing the
required evidence. An HTTP `101` handshake establishes a connection, not
message-level authorization.

## Two-principal sequence

Use synthetic principals A and B with owned test objects. Record the connection
identity and session for each. Compare an authorized subscription/action with
a known object owned by the same principal, then have the other principal
request the same synthetic object or topic. Verify the returned message content
and owner, not just a successful send or status.

Check connection authentication, endpoint and protocol negotiation, message
and topic ownership, tenant subscriptions, session expiry, logout, reconnect,
and broadcast isolation when those features exist. After logout or expiry,
reconnect using the same test client and verify whether prior authority remains.
For browser-origin claims, a non-browser client's configurable `Origin` header
is not a browser-cookie test; require a scoped browser with authenticated
evidence or report the limitation.

## Evidence

Correlate each message with the connection/session identifier, synthetic
principal, request, response, and object owner. Capture handshake and message
bytes through a registered guarded tool, declare saved files with
`evidence_outputs`, and pair each with its authenticating receipt. Never include
live session cookies or bearer tokens in reports.

## Stop Conditions

- Stop when the required client is unavailable or cannot execute through a
  registered guarded path; record the check as blocked or inconclusive.
- Stop if a message reaches a non-test tenant or causes a non-reversible
  state change.
- Stop when an Origin or endpoint is outside the written scope.

## Blocked Actions

Do not use raw sockets, unscoped browser automation, production-user sessions,
high-volume message floods, or a forged Origin accepted by a non-browser client
as proof of cross-site WebSocket hijacking.

## References

- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
