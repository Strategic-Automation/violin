# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes |

## Reporting a Vulnerability

Violin is a **defensive security assessment profile** — it helps authorised testers find and document vulnerabilities in systems they have permission to test.

If you discover a security issue in Violin itself (not a target being tested with Violin):

1. **Do not open a public GitHub issue.**
2. Email the maintainer at the contact address listed on the GitHub profile.
3. Include a clear description, steps to reproduce, and potential impact.

You should receive a response within 48 hours. If the issue is confirmed, a fix will be prioritised and coordinated with your preferred disclosure timeline.

## Scope

This policy covers:

- The `violin_guard.py` validation script
- The `config.yaml` safety configuration
- The `skills/pentest/` playbook methodology
- Distribution and installation mechanisms

What this policy does NOT cover:

- Vulnerabilities discovered **by Violin** during authorised testing (those go in the engagement report)
- Third-party tools (nmap, sqlmap, etc.) that Violin invokes — report those to their respective projects
- The Hermes Agent platform itself — report those at the [Hermes repository](https://github.com/NousResearch/hermes-agent)

## Safe Harbour

We will not pursue legal action against researchers who:

- Report vulnerabilities in good faith
- Follow this disclosure policy
- Do not access or modify user data beyond what's necessary to demonstrate the vulnerability