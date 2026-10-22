# OAuth 2.0 and OpenID Connect — Federation Playbook

Use this guide only when an authorized application exposes a federated login,
authorization-code callback, token exchange, or account-linking flow. Record the
provider, client, redirect URI, issuer, expected subject, and protected action
before testing. OAuth authorization is not itself proof of authentication; use
OpenID Connect identity claims only when the application consumes them.

## Transaction checks

Trace one synthetic transaction through browser/client, authorization server,
callback, token exchange, local account resolution, and the protected resource.
For each boundary, record the value expected, the observed value, and the
principal/resource selected by the relying application.

| Control | Compare | Applicability |
|---|---|---|
| `state` | Initiating session and returned callback transaction | Browser authorization redirects |
| `nonce` | Request value and validated ID token | OIDC flows that send a nonce |
| PKCE | Authorization code challenge and verifier at token exchange | Public clients and flows configured for PKCE |
| Issuer / audience | Configured issuer and client ID against validated token claims | OIDC ID-token consumption |
| Code / client / redirect binding | Code use, registered client, exact redirect URI | Authorization-code flow |
| Account linking | Authenticated local account, provider issuer/subject, explicit link intent | Existing-account linking or provider sign-in |

Use two operator-provided synthetic accounts with distinct provider subjects.
Compare the callback and resulting session for a matched transaction and a
controlled mismatch. Verify which local account and protected object the
application selected. A callback code, `Set-Cookie`, redirect, or token-shaped
string alone is not evidence of account takeover. Do not replay or redeem a real
user's code or token.

## Evidence

Capture the authorized request/response sequence, redacting codes, cookies and
tokens. Save decisive responses under `$ENG_DIR/evidence/vuln-research/` with
`evidence_outputs`, and cite only files sealed by their selected execution
receipt. Record unavailable provider, browser, or test-account controls as
limitations. Confirm impact through the protected resource or resulting
synthetic account identity.

## Stop Conditions

- Stop on a provider or redirect outside the written scope.
- Stop if a probe could link, modify, or access a non-test user account.
- Stop if a state-changing account-link test lacks explicit approval or a
  reversible synthetic account.

## Blocked Actions

Do not harvest credentials, redeem third-party codes, alter provider settings,
use raw browser automation outside the scoped runtime, or infer compromise from
a redirect or cookie alone.

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-18.html)
- [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
