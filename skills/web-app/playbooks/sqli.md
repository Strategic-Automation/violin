# SQL Injection (SQLi)

## Scope and classification

SQL injection occurs when input changes the structure or behavior of a database
operation. Map the test to OWASP WSTG v4.2 procedure IDs and ASVS 5.0.0
requirements where applicable; see `skills/pentest/references/source-provenance.md`.
This playbook is bounded to non-destructive validation on explicitly authorized
inputs. Database enumeration, data extraction, writes, stacked statements,
operating-system interaction, and blind extraction are out of scope unless the
Rules of Engagement explicitly authorize the exact action and data boundary.

## Validation

1. Confirm the endpoint, parameter, identity, and allowed request budget.
2. Capture a benign baseline with stable input and preserve status, relevant
   response content, and timing.
3. Use one minimal, inert input variation and a paired control. Keep the request
   shape, identity, and application state constant.
4. Repeat only as needed within the authorized budget. A database error, status
   code, response length, timing change, or scanner alert alone is not proof.
   Corroborate a repeatable application-visible behavior change that is
   specific to the paired condition and does not expose unrelated data.
5. If authorized source is supplied, trace input through parsing and query
   construction to the handler, then compare sibling routes. Source review guides
   the hypothesis; observed guarded behavior establishes a finding.

Do not use automated tools with extraction, mutation, shell, file, or bypass
features. Do not assume a low tool risk setting makes a request safe. Prefer a
manual, minimal control pair when the tool cannot guarantee the requested
non-destructive boundary.

## Evidence

Save the exact baseline and changed requests/responses, target and parameter,
identity, timing conditions, guard receipt, and the specific repeatable effect
under `$ENG_DIR/evidence/exploitation/sqli/`. Redact credentials and unrelated
data. State what the test can establish and its limits; no finite test proves
absence.

## Stop Conditions

- Stop on unexpected errors, latency/degradation, state changes, sensitive data,
  or evidence that the test may execute a write or disclose unrelated records.
- Stop if a paired control is unstable or the result depends only on timing,
  response length, or an error message.
- Stop before any escalation in payload behavior, automation, request rate, or
  data access without explicit approval.

## Blocked Actions

- Credential or database extraction, table/database enumeration, data dumps,
  destructive or modifying statements, stacked statements, file access, shell
  access, and unapproved automated exploitation.
- Blind character-by-character extraction, high-volume payload sweeps, and
  evasion or WAF bypass recipes.
- Claiming SQLi from a status code, timing delta, length change, generic error,
  or tool output without a decisive, controlled behavior change.
