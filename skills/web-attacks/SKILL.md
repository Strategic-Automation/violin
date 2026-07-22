---
name: web-attacks
description: "Use when an authorized engagement's PTT or hypothesis identifies web injection: SQLi, XSS, command injection, SSRF, or path traversal. Select it through the Violin receipt flow, then load only the matching playbook for safe validation and evidence."
version: 1.0.0
author: Violin
license: MIT
metadata:
  hermes:
    tags: [pentest, web, owasp, injection]
    related_skills: [pentest, access-control]
---

# Web Application Injection Attacks

## Overview

On-demand reference skill for web-application injection vuln classes. The `pentest` orchestrator routes here when a discovery endpoint or PTT entry matches one of these classes. Each class is a self-contained `playbooks/<class>.md` loaded via `read_file` only when needed — progressive disclosure, not eager loading.

## When to Use

- SQL Injection, XSS, Command Injection, SSRF, or Path Traversal identified or scoped.
- A recon/endpoint pattern (e.g. `?q=`, `/api/...`) maps to an injection sink.

## Playbook Routing

| Class | Playbook |
|-------|----------|
| SQL Injection | `playbooks/sqli.md` |
| Cross-Site Scripting | `playbooks/xss.md` |
| Command Injection | `playbooks/command-injection.md` |
| Server-Side Request Forgery | `playbooks/ssrf.md` |
| Path Traversal / LFI | `playbooks/path-traversal.md` |

## Common Pitfalls

- Every payload runs inside the engagement runner — never host-eval an injected string.
- Read the playbook's `## Stop Conditions` and `## Blocked Actions` before exploit validation.
- Store proof under `$ENG_DIR/evidence/exploitation/<class>/`; redact secrets.

## Verification Checklist

- [ ] Engagement bootstrapped (`violin_guard.py check-bootstrap` exit 0)
- [ ] Playbook loaded for the matched class only
- [ ] Evidence written under `$ENG_DIR/evidence/`
