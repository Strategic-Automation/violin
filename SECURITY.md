# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes |

## Reporting a Vulnerability

Violin is a **defensive security assessment profile** — it helps authorised testers find and document vulnerabilities in systems they have permission to test.

If you discover a security issue in Violin itself (not a target being tested with Violin):

1. **Do not open a public GitHub issue.**
2. Use the repository's private vulnerability-reporting channel when available; otherwise email the maintainer at the contact address listed on the organisation profile.
3. Include a clear description, steps to reproduce, and potential impact.

If the issue is confirmed, remediation and disclosure timing will be coordinated with the reporter.

## Scope

This policy covers:

- The required `plugins/violin_guard/` execution guard and registered tools
- The `scripts/violin_guard.py` diagnostic/admin entrypoint and release smoke helpers
- The `config.yaml` safety configuration
- The routed methodology under `skills/pentest/`, `skills/web-attacks/`, and `skills/access-control/`
- Distribution and installation mechanisms

What this policy does NOT cover:

- Vulnerabilities discovered **by Violin** during authorised testing (those go in the engagement report)
- Third-party tools (nmap, sqlmap, etc.) that Violin invokes — report those to their respective projects
- The Hermes Agent platform itself — follow the [Hermes security policy](https://github.com/NousResearch/hermes-agent/security)

## Safe Harbour

We will not pursue legal action against researchers who:

- Report vulnerabilities in good faith
- Follow this disclosure policy
- Do not access or modify user data beyond what's necessary to demonstrate the vulnerability
