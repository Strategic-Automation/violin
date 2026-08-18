# API Security Testing Playbook

## Overview

Systematic methodology for auditing REST, GraphQL, SOAP, and WebSocket API endpoints.

> **Full Payload Reference:** See `skills/pentest/references/api-testing.md` for complete SOAP WSDL enumeration, XXE payloads, GraphQL Introspection/Batching queries, OWASP API Top 10 property injection examples, and specialized API CLI tool syntax (`Arjun`, `ffuf`, `Nuclei`, `kiterunner`).

Target-touching actions MUST use typed `violin_*` tools under repo root `$ENG_DIR`.

## OWASP API Security Top 10 Reference

| Tag | Category | Core Mechanism |
|---|---|---|
| API1 | **BOLA / IDOR** | Accessing objects via guessable/modified IDs without caller authorization checks |
| API2 | **Broken Auth** | Weak token handling, uninvalidated sessions, JWT manipulation, missing MFA |
| API3 | **Property-Level Auth** | Mass assignment, excessive property exposure in response bodies |
| API4 | **Unrestricted Resource Consumption** | Missing rate limits leading to resource exhaustion |
| API5 | **Broken Function-Level Auth** | Accessing administrative endpoints using low-privilege caller tokens |
| API6 | **Sensitive Flow Exploitation** | Scraping, scalping, business logic bypasses via API calls |
| API7 | **SSRF** | Unvalidated user-supplied URLs fetched by backend API servers |
| API8 | **Security Misconfiguration** | Verbose errors, default creds, CORS misconfigurations |
| API9 | **Improper Inventory** | Exposed staging/dev endpoints, un-versioned API surfaces |
| API10 | **Unsafe API Consumption** | Unvalidated input consumed from third-party APIs |

---

## Vulnerability Types & Testing Techniques

### 1. BOLA / IDOR (Broken Object Level Authorization)

Canonical playbook: `identity-auth` → `playbooks/idor-access-control.md`
(classification, probes, evidence standard, PoC).

**Quick check probes** (before loading the dedicated playbook):
```bash
# Sequential ID range
for id in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code} /api/v2/users/$id\n" -H "Authorization: Bearer ***" "https://target/api/v2/users/$id"
done

# Check another user's order
curl -s -H "Authorization: Bearer ***" "https://target/api/v2/orders/ORDER_OF_ANOTHER_USER"
```

### 2. Broken Authentication

Canonical playbooks: `identity-auth` → `playbooks/auth-bypass.md` (default
creds, auth parameter manipulation) and `playbooks/jwt-attacks.md` (decode,
alg:none, HS256 crack).

**JWT decode probe:**
```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'
```

**TOTP/2FA bypass** — check if the `totp` secret is stored in the JWT payload:
```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | grep -o '"totpSecret":"[^"]*"'
```
See `identity-auth/playbooks/auth-bypass.md` §2FA Bypass for the full matrix.

### 3. Excessive Data Exposure & Mass Assignment
- **Mechanism**: Backend serializes raw database objects or accepts un-whitelisted JSON payload keys.
> **Safety Warning:** Only perform a live mass-assignment probe when the RoE provides a disposable test account. Never modify real accounts as proof.
- **Probe Commands**:
```bash
# Data exposure audit
curl -s -H "Authorization: Bearer $TOKEN" "https://api.target.com/api/v2/users/me" | jq 'keys'

# Check for sensitive fields in API responses
for field in password password_hash ssn credit_card secret api_key token internal_id role is_admin; do
  if echo "$response" | jq -e ".$field" > /dev/null 2>&1; then
    echo "[!] SENSITIVE FIELD FOUND: $field"
  fi
done

# Mass assignment role elevation probe
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"user1","email":"user1@test.com","role":"admin","is_admin":true}' \
  "https://api.target.com/api/v2/users/me"
```
- **Evidence**: Response JSON includes sensitive internal fields (`password_hash`, `role`, `internal_id`) or payload accepts unauthorized property mutations.

### 4. Broken Function Level Authorization (BFLA)
- **Mechanism**: Privileged endpoints lack role checks.
- **Probe Commands**:
```bash
# Low-privilege caller probing administrative endpoints
curl -s -H "Authorization: Bearer $LOW_PRIV_TOKEN" "https://api.target.com/api/v2/admin/users"
curl -s -H "Authorization: Bearer $LOW_PRIV_TOKEN" "https://api.target.com/api/v2/admin/system/status"
```
- **Evidence**: HTTP 200 with administrative data for non-admin tokens.

### 5. GraphQL Vulnerabilities
- **Mechanism**: Introspection enabled, query depth/batching abuse, field exposure.
- **Probe Commands**:
```bash
# Introspection query
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' "https://api.target.com/graphql"

# Deep nesting depth probe (3-5 levels max for safe testing)
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{user{friends{friends{friends{id}}}}}"}' "https://api.target.com/graphql"
```
- **Evidence**: Full schema dump returned or un-throttled array batching permitted.

### 6. Missing Rate Limiting (absence proof)

A missing rate limit is proven by **absence**, not by a single response. To
demonstrate it, fire a burst of identical requests and capture every status
line; the decisive evidence is that full run — a dozen identical status codes
with **no counter-signal** (`429`, `throttle`, `rate-limit`, `lockout`)
anywhere. It lives in the command output, not the finding prose.

**A prose note is not evidence.** Writing a file that says "rate limiting not
extensively probed" or "no 429 observed during normal testing" records zero
status codes, so the finding has nothing to stand on even though a coverage
cell cites the path. The decisive artifact is the literal run of status
lines. If you did not run the burst, you have not tested the vector — do not
write a placeholder and move on.

- Pick a state-changing auth endpoint (default: `POST /api/v1/auth/login`).
- Fire **10 rapid identical requests** in one command whose stdout captures
  every status line, e.g.:

```bash
for i in $(seq 1 10); do
  curl -sS -o /dev/null -w "%{http_code}\n" \
    -X POST "$TARGET/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"email":"nonexistent@x.com","password":"wrong"}'
done | tee $ENG_DIR/evidence/vuln-research/no_rate_limit_login.txt
```

- Do NOT truncate to a single status and do NOT suppress the per-request
  codes: the bundle must show the full run (e.g. ten `401` lines).
- If every request returns the same code and **no** `429`/`throttle` appears,
  the rate limit is absent — record the file as the decisive evidence and
  note "10 identical 401s, zero 429" in the finding.
- If any `429` or throttling response appears, the control exists — mark the
  vector `not_applicable` (do not force a finding).

---

## Hidden, Deprecated, and OpenAPI Asset Discovery

When API behavior does not match visible documentation or UI:

1. Inspect OpenAPI/Swagger assets (`/api-docs/*`, `swagger-ui-init.js`, `swagger-initializer.js`, `/v2/api-docs`) and JS bundles for unlinked routes.
2. Discover hidden API parameters via `arjun`:
```bash
arjun -u https://api.target.com/api/v2/users -m GET,POST -oJ $ENG_DIR/evidence/exploitation/api-security/arjun-params.json
```
3. Test versioned and legacy paths (`/api/v1`, `/api/v2`, `/rest`, `/b2b`, `/legacy`) before assuming a visible route is the only backend endpoint.
4. Check content negotiation: test XML/SOAP `Content-Type` / `Accept` headers on modern JSON endpoints for legacy parser fallback.
5. Compare Bearer tokens, session cookies, and API keys; some legacy endpoints honor only specific auth contexts.

---

## Remediation Guidance

When documenting API vulnerabilities in the reporting phase, map findings to these canonical remediations:

| Vulnerability | Remediation Approach |
|---|---|
| **BOLA / IDOR** | Implement authorization checks on every object access via resource ID. Validate the authenticated user owns or has permissions to access the requested ID. |
| **Broken Auth** | Implement strict token expiration, token invalidation on logout (blocklists), and secret rotation. Prefer short-lived tokens with HTTPOnly cookies. |
| **Excessive Data Exposure** | Filter response objects at the API controller layer (use DTOs or `@JsonView`). Never expose full internal database entities or sensitive fields. |
| **Lack of Rate Limiting** | Apply per-user and per-IP rate limits using sliding windows. Return HTTP `429 Too Many Requests` with a `Retry-After` header on limit breaches. |
| **BFLA** | Enforce role-based access control (RBAC) at routing/middleware level for all administrative endpoints; enforce default-deny access rules. |
| **Mass Assignment** | Use explicit DTOs/whitelists for request parameter binding. Never bind client payloads directly to internal database domain models. |
| **Security Misconfiguration** | Disable verbose stack traces in production, configure restrictive CORS origins, remove unused HTTP methods, and audit default credentials. |
| **Injection** | Use parameterized queries and ORM query builders for database interaction. Sanitize and validate all incoming request parameters. |
| **Improper Inventory** | Version all API endpoints (`/v1`, `/v2`). Deprecate and remove legacy/staging endpoints, maintaining a live catalog of active APIs. |
| **Unsafe Consumption** | Validate and sanitize data received from third-party APIs before processing; enforce TLS and allowlist outbound endpoints. |
| **GraphQL Introspection & Depth** | Disable introspection in production. Enforce max query depth limits (5–7 levels) and cost analysis to prevent query-based resource exhaustion. |
| **GraphQL Batching** | Apply per-user rate limits across batched query arrays, not just single HTTP request wrappers. |
| **SOAP / XXE** | Disable external DTD and entity resolution in XML parsers (`disallow-doctype-decl`). Prefer JSON APIs where feasible. |

---

## Tooling Matrix

| Tool | Purpose | Primary Command |
|---|---|---|
| `violin_exec` (httpx) | Fast API endpoint discovery & status code mapping | `violin_exec(eng_dir=..., command="httpx -mc 200,204,301,302,307,401,403 -status-code <target>", phase=...)` |
| `violin_exec` (ffuf) | API parameter & endpoint fuzzing | `violin_exec(eng_dir=..., command="ffuf -w /usr/share/wordlists/api/common_api_paths.txt -u <target>/FUZZ", phase=...)` (verify an existing wordlist) |
| `violin_exec` (nuclei) | Automated API vulnerability template scanning | `violin_exec(eng_dir=..., command="nuclei -u <target> -tags api", phase=...)` |
| `kiterunner` | High-speed API route discovery via OpenAPI/Swagger specs | `kr scan https://api.target.com/ -w /usr/share/seclists/Discovery/Web-Content/api/kiterunner.wordlist` |

---

## Endpoint & Auth Discovery Rules
1. **OpenAPI / Swagger Inspection**: Check `/api-docs/*`, `swagger-ui-init.js`, `swagger-initializer.js`, and JS bundles for undocumented endpoints.
2. **Version & Legacy Routing**: Test versioned paths (`/api/v1`, `/api/v2`, `/rest`, `/b2b`, `/legacy`) before concluding an endpoint is absent.
3. **Auth-Context Split**: Bearer tokens, cookies, and browser UI sessions are not interchangeable. Test endpoints with actual UI auth context.

---

## Evidence & Verification Standard
Collect for every finding:
1. Full HTTP Request (Method, URL, Headers, Body).
2. Full HTTP Response (Status, Headers, Response Body).
3. Auth Context Differential (Token A vs Token B vs Unauthenticated).
4. Save raw evidence to `$ENG_DIR/evidence/exploitation/api-security/`.

---

## Safe Proof of Concept (PoC)

Safe PoCs demonstrate an API vulnerability **without** causing harm:

### PoC: Unauthorized Data Access (Read-Only)

See `identity-auth` → `playbooks/idor-access-control.md` for the IDOR PoC
script and evidence standard.

### PoC: Sensitive Data Exposure

```bash
#!/bin/bash
# SAFE PoC: Demonstrate excessive data exposure in API response

echo "[*] Testing: Excessive Data Exposure"
echo "[*] Target: $TARGET/api/v2/users/me"

response=$(curl -s -H "Authorization: Bearer $TOKEN_A" \
  "$TARGET/api/v2/users/me")

echo "[+] Full API response:"
echo "$response" | jq '.'

# Check for sensitive fields
for field in password password_hash ssn credit_card secret api_key token internal_id role is_admin; do
  if echo "$response" | jq -e ".$field" > /dev/null 2>&1; then
    echo "[!] SENSITIVE FIELD FOUND: $field"
  fi
done
```

## Evidence & Verification Standard
Collect for every finding:
1. Full HTTP Request (Method, URL, Headers, Body).
2. Full HTTP Response (Status, Headers, Response Body).
3. Auth Context Differential (Token A vs Token B vs Unauthenticated).
4. Save raw evidence to `$ENG_DIR/evidence/exploitation/api-security/`.

---

## Safety & Stop Conditions
> Baseline safety, forbidden actions, and stop conditions: See `skills/pentest/references/shared-safety.md` and `.hermes.md`.
- Read-only testing unless write scope is explicitly approved.
- Do NOT perform sustained high-rate fuzzing, automated scraping of all records, or DoS query batching (e.g. deep recursive GraphQL queries causing measurable latency).

---

## References
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- PortSwigger API Security: https://portswigger.net/web-security/api
- SecLists API Wordlists: `/usr/share/seclists/Discovery/Web-Content/api/`
