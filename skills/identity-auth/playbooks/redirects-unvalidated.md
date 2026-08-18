# Unvalidated Redirects — Playbook

## Vulnerability Description

**OWASP:** A01:2021 — Broken Access Control (redirect as access bypass)
**CWE:** CWE-601 (URL Redirection to Untrusted Site)

Unvalidated redirect (open redirect) occurs when an application accepts user-controlled input that specifies a redirect destination, without validating that the destination is safe. Attackers can use this to phish users, bypass access controls, or trick users into visiting malicious sites.
---

## Types

| Type | Description | Indicators |
|------|-------------|------------|
| **Open Redirect** | Any external URL accepted as redirect target | `?redirect=http://evil.com`, `?next=//evil.com` |
| **Allowlist Bypass** | Domain allowlist can be bypassed with URL tricks | Subdomain tricks (`target.com.evil.com`), path tricks (`target.com/../evil.com`) |
| **URL Parsing Confusion** | Different URL parsers (client vs server) interpret the URL differently | `https://evil.com@target.com`, `//evil.com`, `///evil.com` |
| **Protocol Relative** | Accepts `//evil.com` which inherits current protocol | Double slash at start of redirect param |
| **JavaScript-based Redirect** | Client-side `window.location` manipulation via user input | Hash fragment, `postMessage` targets |
| **Meta Refresh** | HTML `<meta http-equiv="refresh">` controlled by user input | Stored XSS + redirect chaining |

---

## Detection

### Open Redirect Testing

```bash
# Test common redirect parameter names
for param in "redirect" "next" "url" "return" "returnUrl" "return_to" "goto" \
  "target" "destination" "redirect_uri" "redirectUrl" "callback" "continue" \
  "forward" "page" "path" "view" "ref" "out" "domain"; do
  code=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
    "https://target.com/login?${param}=http://evil.com")
  echo "$param → $code"
done

# Test with URL-encoded payloads
curl -v "https://target.com/login?redirect=http%3A%2F%2Fevil.com%2F"
curl -v "https://target.com/login?next=//evil.com"
curl -v "https://target.com/login?url=/\\evil.com"
```

### Systematic open-redirect probe

Run this as a structured loop, not a single test, because redirects hide in
unexpected routes and parameter names:

1. **Collect candidate routes**: every route that takes a URL-ish input —
   login, logout, register, checkout, product detail, search, error pages,
   OAuth/callback handlers, password reset ("return to"), and any route that
   renders "you will be redirected" text.
2. **Try each redirect parameter name** on every candidate route:
   `redirect`, `next`, `url`, `return`, `returnUrl`, `return_to`, `dest`,
   `destination`, `target`, `goto`, `callback`, `continue`, `checkout_url`,
   `redirect_url`, `redirect_uri`, `RelayState`.
3. **Each probe must capture the response headers** (`curl -i` / `-sv`) and
   check for a `Location:` header whose host is NOT the target's domain.
   A 3xx without a Location header is not proof; an external Location is.
4. **Follow every external-looking Location** to confirm the redirect lands
   off-target (`Location: http://<external>`) — that is the decisive proof.
5. **Bypass the allowlist when present**: if probes return a generic redirect
   or an allowlisted-page redirect, embed an allowlisted domain as a
   *parameter value* in the redirect target so the naive substring check
   passes while the browser/curl still lands on the external host, e.g.
   `?redirect=https://external.example/path?allowlisted=target.com`. Also try
   protocol-relative (`//external.example`), userinfo (`https://external@target.com`),
   backslash, double-encoding, and fragment tricks.
6. **Record negative results**: for every route×param tried, save the response
   (status + Location or absence) under `evidence/vuln-research/` so the
   coverage matrix can disposition the redirect cell with proof.

## Allowlist Bypass Techniques

```bash
# Subdomain trick
curl -v "https://target.com/login?redirect=https://target.com.evil.com/phish"

# Path traversal in host
curl -v "https://target.com/login?redirect=https://target.com/../evil.com"

# URL parsing confusion
curl -v "https://target.com/login?redirect=https://evil.com@target.com"
curl -v "https://target.com/login?redirect=https://evil.com%2F@target.com"

# Double-dot bypass
curl -v "https://target.com/login?redirect=https://evil..com"

# Encoding bypass
curl -v "https://target.com/login?redirect=https://target.com%2Feval%2Fredirect?url=http://evil.com"

# Fragment-based
curl -v "https://target.com/login?redirect=#https://evil.com"

# Data URI
curl -v "https://target.com/login?redirect=data:text/html,<script>location='http://evil.com'</script>"
```

### Blind Redirect Detection

```bash
# Use a collaborator/interact.sh URL to detect server-side redirects
curl -v "https://target.com/login?redirect=https://your-collaborator.oastify.com"

# Check response headers for redirect
curl -s -D - "https://target.com/login?redirect=http://evil.com" | head -20
# Look for: Location: http://evil.com, 302 Found
```

---

## Safe Proof of Concept

```bash
# Safe: Demonstrate open redirect to a controlled, benign domain
curl -v "https://target.com/login?redirect=https://example.com"
# Expected if vulnerable: 302 Location: https://example.com
# Safe: No user interaction — just showing header response

# Safe: Demonstrate allowlist bypass with subdomain trick
curl -v "https://target.com/login?redirect=https://target.com.evil.com"
# If this redirects, the allowlist regex is bypassable
```

**Safe PoC rules:**
- Redirect to example.com or similar benign domains — never to malicious or uncontrolled sites
- Do not chain open redirect with phishing (even for proof)
- Document the redirect header — no need to follow it

---

## Evidence

```
**Vulnerability:** Unvalidated Redirect — Open Redirect
**URL:** https://target.com/login?redirect=http://evil.com
**Parameter:** redirect
**Type:** Open Redirect

**HTTP Request:**
  GET /login?redirect=http://evil.com HTTP/1.1
  Host: target.com

**HTTP Response:**
  HTTP/1.1 302 Found
  Location: http://evil.com
  Content-Length: 0

**Proof:** Server returned 302 redirect to external domain (evil.com).
**Remediation:** Validate redirect targets against a strict allowlist. Reject any URL not on the allowlist.
```

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/redirects-unvalidated/<finding>.*`
- Screenshots (if applicable) → `$ENG_DIR/evidence/exploitation/screenshots/`
- Request/response pairs → `$ENG_DIR/evidence/exploitation/http/`

---

## Stop Conditions
- Generic baseline — see `references/shared-safety.md` §Generic Stop Conditions (pause on unexpected behavior, scope breach, or WAF/IDS trip).

## Blocked Actions
- Generic baseline — see `.hermes.md` §Forbidden Behaviour (destructive DB ops, exfiltration beyond PoC, persistence, lateral movement all prohibited there).

## Remediation

| Measure | Description |
|---------|-------------|
| **Strict allowlist** | Only allow redirects to explicitly allowed domains/paths |
| **Relative paths only** | Accept only relative redirects (`/dashboard`, `/profile`) — reject absolute URLs |
| **No user-controlled redirect** | Use server-side maps (redirectId=abc → resolves to /dashboard on server) |
| **Validate after decoding** | URL-decode input before validation — catch double-encoding bypasses |
| **Reject protocol-relative** | Block redirect URLs starting with `//` |
| **Canonicalize before check** | Normalize URLs before comparing to allowlist |

---
