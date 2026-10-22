# API Security Testing

Target-touching requests must use registered `violin_*` tools with scope,
phase, and approval gates. Map procedures to versioned OWASP references in
`skills/pentest/references/source-provenance.md`. HTTP status, schema visibility,
or a tool alert alone is not a confirmed vulnerability.

## Authorization and object access

Use two explicitly provisioned synthetic principals and known-owned fixtures.
For each endpoint, record route, method, caller role, object/tenant, operation,
and response content or effect. Compare an owner's allowed operation with a
non-owner's request for that same object. Use disposable fixtures for mutation
tests and restore them within the approved workflow. A low-privilege `200` is
not sufficient without protected content or an unauthorized effect.

For property-level authorization, submit only a harmless, reversible field on
a synthetic account. Compare the before/after state through an authoritative
read. Do not change roles, balances, ownership, or real user records as proof.
For excessive response data, identify the specific sensitive field, its owner,
why the caller cannot access it, and the response evidence; redact the value.

## GraphQL

Test authorization at the root and nested resolver for an owned fixture using
the same query as a non-owner. Preserve the query, roles, object ownership, and
relevant returned content. Introspection visibility or HTTP 200 alone is not a
finding. Test aliases or batching only if the deployed endpoint actually
supports them, and only within the authorized request budget to compare
per-operation authorization. Avoid deep or expensive queries. Record whether
batching was absent, unsupported, or left untested and why.

## Rate limits and resource controls

Follow written request, concurrency, account-lockout, and state-change limits.
Where the rules are silent, use the smallest sequential sample that can answer
the question and obtain approval before increasing frequency or concurrency.
Prefer synthetic accounts and non-destructive operations. Stop on throttle,
lockout, CAPTCHA, degradation, or unexpected state change. Do not use bursts,
account rotation, alternate IPs, or changed identities/headers to evade a
control.

Record endpoint and operation, identity, request count and interval, ordered
responses, control, and limitations. No throttle observed in a bounded sample
describes only those requests and that interval; it does not prove universal
absence. A suspected control gap needs a demonstrated impact path. A failed
tool call is not a negative test, and `not_applicable` is only for an absent or
irrelevant feature supported by evidence.

## Endpoint and source reconciliation

When schemas or source are supplied, map `route × role × object/tenant ×
operation`; include source artifact path and revision, auth and tenant selection,
and the compared sibling handler family. Use this to identify test candidates,
then prove any issue with a guarded request and protected object/effect. Source
is not required for black-box coverage; record unavailable source as a limit,
not a failed test.

## Evidence

Save exact paired requests/responses, synthetic principal roles, fixture setup
and ownership, guard receipts, and authoritative state reads under
`$ENG_DIR/evidence/exploitation/api-security/`. Redact credentials and unrelated
data. State the tested operation, control, observed effect, request budget, and
limits of inference.

## Stop Conditions

- Stop on scope uncertainty, rate controls, unexpected state, service
  degradation, or exposure of real sensitive data.
- Stop before increasing concurrency, request rate, query cost, or mutation scope
  without approval.
- Stop if synthetic principals or known-owned fixtures are unavailable for an
  authorization claim.

## Blocked Actions

- Unbounded fuzzing, credential attacks, resource-exhaustion queries, real-user
  mutations, role/balance changes, and testing with data outside scope.
- Treating HTTP 200, introspection, a status-only response, or source-only
  evidence as proof of unauthorized access.
