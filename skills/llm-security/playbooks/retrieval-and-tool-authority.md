# LLM Retrieval and Tool Authority

Assess authorization at the data and action boundary, not only at the model
prompt. Use harmless unique marker documents, two synthetic principals or
tenants, and an isolated test session. Record which principal uploaded or owns
each marker, the query/session, retrieval result, cache/session context, and the
effective identity and approval binding of any proposed tool call.

## Retrieval and memory

Trace a marker from its source through indexing, retrieval filters, reranking,
memory, and response. Compare an owner query with a non-owner query, then test a
new session and any documented shared cache boundary. A model-generated mention
without the marker present in retrieved context is not proof of retrieval
authorization failure. Conversely, marker text returned to the wrong tenant or
session is decisive content evidence. Do not seed real secrets or unrelated
personal data.

## Tool and agent authority

Use a harmless tool action in an isolated fixture. Compare the authenticated
principal and authorization decision for a direct request and a model-proposed
tool call. Verify the effective identity, approval state, and argument binding
at execution time; text in a prompt or a model refusal is not an authorization
control. Do not invoke destructive, external, or privileged tools.

## Evidence

Save marker ownership, tenant/session setup, exact query, retrieved context or
tool proposal, effective principal and approval result, observed content/effect,
guard receipt, and limitations. Redact unrelated content and credentials.

## Stop Conditions

- Stop if a marker crosses a real tenant boundary or real sensitive data
  appears; retain only the minimum redacted evidence and notify the operator.
- Stop before any external, destructive, privileged, or irreversible action.
- Stop when the effective identity, cache boundary, or approval state cannot be
  observed; report the limitation.

## Blocked Actions

- Prompting for real secrets, extracting unrelated memory, cross-tenant writes,
  external callbacks, destructive actions, or bypassing an approval gate.
- Treating refusal text, a guessed answer, a model statement, or prompt
  compliance alone as proof of access to protected data or tool authority.
