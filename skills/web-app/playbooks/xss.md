# Cross-Site Scripting (XSS)

Map procedures to the versioned WSTG and ASVS references in
`skills/pentest/references/source-provenance.md`. Use a synthetic account and
harmless marker input. Target requests and browser-driven checks must remain
within the authorized, scope-enforcing runtime.

## Trace and validate

For each input, trace `source → transformations → sanitizer/encoder → sink →
browser context`. Record whether the context is HTML text, attribute, URL,
JavaScript, CSS, or DOM API, and whether the transformation is context-appropriate.
An input reflected in HTML or stored as text is not itself a vulnerability.

- **Reflected:** use one inert marker in a synthetic request and inspect the
  exact response context and browser interpretation.
- **Stored:** submit from principal A to a disposable fixture, then load the
  rendered content as principal B. Revalidate B's session before any sensitive
  context. Remove the fixture through the approved workflow.
- **DOM-based:** use the supported browser or supplied source to trace a
  controllable source to a dangerous sink. If browser execution is unavailable,
  report that as a capability limitation; source analysis alone remains a
  candidate until behavior is observed.
- **`postMessage` or cross-origin paths:** test only when that feature exists and
  an authorized browser context can observe origin and message handling.

Use a harmless, self-contained execution marker only in an isolated page and
synthetic account. Do not access cookies, local storage, credentials, or browser
data; do not make external callbacks. A reportable proof identifies the
untrusted input, context, unsafe transformation/sink, principal viewing it, and
the observed browser-side effect. CSP or a scanner result alone is not proof.

## Evidence

Save exact input and response, the relevant encoded/rendered context, source and
revision when available, browser screenshot or execution observation, synthetic
principal/fixture, cleanup, guard receipts, and limits under
`$ENG_DIR/evidence/exploitation/xss/`. Redact unrelated data.

## Stop Conditions

- Stop if a real user's context would render the content or if the test could
  persist beyond the synthetic fixture.
- Stop if any real credential, session data, or unrelated personal information
  appears.
- Stop when browser execution or the rendering context cannot be observed; keep
  the result as a candidate and report the limitation.

## Blocked Actions

- Credential/session theft, cookie or storage reads, keylogging, phishing UI,
  external callbacks, blind payloads that target administrators, or persistence
  in real user content.
- WAF/filter evasion payload catalogs, unbounded fuzzing, or claims based only
  on reflected text, source patterns, response status, or scanner output.
