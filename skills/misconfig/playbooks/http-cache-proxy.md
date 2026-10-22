# HTTP Cache and Forwarded-Header Trust Review

Use this guide only for an explicitly authorized HTTP origin and, when present,
the in-scope proxy or cache. Use harmless, owned canary content and two
synthetic principals. Ordinary cache/header tests do not validate request
smuggling or raw HTTP framing.

## Controlled checks

Record the proxy/origin boundary, authentication mechanism, path normalization,
cache key inputs, `Vary` behavior, forwarded-header contract, and any signed
response or URL. Use an owned synthetic route or object and compare:

1. A cold request as principal A.
2. A repeated request as A to identify an origin response versus a cache hit.
3. A request for the same safe path as principal B.
4. A control with an ordinary, authorized path/header value and a clean-up or
   expiry check.

Only claim cross-user impact if B receives A's harmless canary or an observable
protected effect. Assess `Host`, forwarded host/scheme, path normalization,
authentication partitioning, signed responses and expiry only where the
deployment actually uses them. Cache headers, timing, status, or a response
variation alone are candidates, not proof. Do not contaminate shared public
caches.

## Evidence

Capture exact guarded request/response pairs and label each principal, cache
state, path and origin result. Save any response body under
`$ENG_DIR/evidence/vuln-research/` using `evidence_outputs`; cite only bytes
sealed by the selected receipt.

## Stop Conditions

- Stop before changing or purging shared cache entries outside a disposable
  test namespace.
- Stop if the test could expose another customer's content or alter a signed
  production URL.
- Record unsupported proxy/cache visibility as a limitation.

## Blocked Actions

No shared-cache poisoning, cache-bombing, raw H1/H2 framing, request
desynchronization, same-connection smuggling, unbounded variants, or public
cache contamination.

## References

Use the versioned WSTG procedures and source provenance recorded in
`skills/pentest/references/source-provenance.md` where applicable.
