---
name: access-control
description: "Use when access-control vuln classes surface (authentication bypass, JWT attacks, IDOR). Load the matching playbook/ file for detection, token analysis, and evidence templates."
version: 1.0.0
author: Violin
license: MIT
metadata:
  hermes:
    tags: [pentest, access-control, auth, owasp]
    related_skills: [pentest, web-attacks]
---

# Access Control Vulnerabilities

## Overview

On-demand reference skill for broken-access-control vuln classes. The `pentest` orchestrator routes here when a discovery endpoint or PTT entry matches authentication/authorization weakness. Each class is a self-contained `playbooks/<class>.md` loaded via `read_file` only when needed.

## When to Use

- Authentication Bypass, JWT Attacks, or IDOR / broken access control identified or scoped.
- An endpoint pattern (e.g. `/api/user/{id}`, `/admin`) maps to an authz boundary.

## Playbook Routing

| Class | Playbook |
|-------|----------|
| Authentication Bypass | `playbooks/auth-bypass.md` |
| JWT Attacks | `playbooks/jwt-attacks.md` |
| IDOR / Broken Access Control | `playbooks/idor-access-control.md` |

## Common Pitfalls

- Read-only token analysis first; never forge tokens to mutate data without explicit authorization.
- Redact actual credentials/sessions in chat and evidence; store minimal proof under `$ENG_DIR/evidence/`.
- Read the playbook's `## Stop Conditions` and `## Blocked Actions` before exploit validation.

## Verification Checklist

- [ ] Engagement bootstrapped (`violin_guard.py check-bootstrap` exit 0)
- [ ] Playbook loaded for the matched class only
- [ ] Evidence written under `$ENG_DIR/evidence/`
