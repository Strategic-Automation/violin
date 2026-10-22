# SAML 2.0 Relying-Party Validation

Load this guide when an authorized application consumes SAML responses or
assertions. Identify the service provider, identity provider, assertion
consumer service (ACS), expected subject, and protected resource. Test only
operator-provided synthetic identities and assertions.

## Validation workflow

Trace the response received at the ACS to the exact assertion element used to
create the application session. Review supplied configuration and source for
issuer, destination/recipient, audience restriction, `InResponseTo`, time
conditions, replay handling, signature trust and reference resolution. Confirm
that the signed element is the same identity and claims object the application
consumes; a valid signature on one element does not authenticate a different
unsigned element.

Use a paired control: a valid assertion for synthetic account A and a
flow-specific, harmless mismatch such as an audience, recipient, or request
correlation mismatch. Where authorized test infrastructure supports it, verify
that a previously consumed assertion cannot create another session. Record the
expected relying-party identity and the protected resource actually returned.
Do not remove a signature or alter a production assertion to manufacture a
finding. A redirect, accepted HTTP response, or session cookie alone does not
prove an authentication bypass.

## Evidence

Save redacted test assertions or decoded claim summaries and the corresponding
guarded request/response bytes under `$ENG_DIR/evidence/vuln-research/`. Preserve
which assertion element was signed and consumed, the synthetic principal, and
the result at the protected resource. Declare output files with
`evidence_outputs` and cite them only with their authenticating receipt.

## Stop Conditions

- Stop when an IdP, ACS, audience, or account is outside the written scope.
- Stop if the only available assertion belongs to a real user or cannot be
  safely reset.
- Record browser or IdP access gaps as blocked or inconclusive; do not invent
  credentials or treat source-only suspicion as runtime proof.

## Blocked Actions

Do not forge assertions for real principals, acquire signing keys, downgrade
signature algorithms, replay production tokens, or use unscoped browser tools.

## References

- [OASIS SAML 2.0 Profiles, approved specification](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [OASIS SAML 2.0 Core, approved specification](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
