---
name: web-app
description: "Web application testing: injection and client-side flaws."
version: 2.0.0
author: Violin
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [pentest, web, owasp, injection, client-side]
    related_skills: [pentest, identity-auth, api-testing, business-logic]
---

# Web Application Security Testing

On-demand skill for web application input-validation and client-side vulnerability classes. The `pentest` orchestrator routes here when a discovered surface matches one class below. Load only the matched playbook with `read_file`; do not eagerly load every playbook.

## When to Use

- A web route, parameter, body field, upload, parser, template, or client-side sink is in scope.
- Recon identifies an injection sink, unsafe deserialization, XML parser, or JavaScript object merge.
- Do not use for authorization/session flaws, API protocol coverage, or workflow abuse; use the routed specialist skill.

## Playbook Routing

| Class | Playbook |
|---|---|
| SQL Injection | `playbooks/sqli.md` |
| Cross-Site Scripting | `playbooks/xss.md` |
| Command Injection | `playbooks/command-injection.md` |
| Server-Side Request Forgery | `playbooks/ssrf.md` |
| Path Traversal / LFI | `playbooks/path-traversal.md` |
| Server-Side Template Injection | `playbooks/ssti.md` |
| XXE / XML Entity Injection | `playbooks/xxe.md` |
| NoSQL Injection | `playbooks/nosql-injection.md` |
| LDAP Injection | `playbooks/ldap-injection.md` |
| XPath Injection | `playbooks/xpath-injection.md` |
| Prototype Pollution | `playbooks/prototype-pollution.md` |
| Insecure Deserialization | `playbooks/deserialization.md` |
| Improper Input Validation | `playbooks/input-validation.md` |

## Common Pitfalls

- Run target-touching checks only through the authorized Violin execution tools.
- Read the matched playbook's stop conditions before validation.
- Store redacted proof under `$ENG_DIR/evidence/exploitation/<class>/`.

## Verification Checklist

- [ ] Engagement bootstrap and scope validation succeeded.
- [ ] The matched playbook alone was loaded and bound to the PTT task.
- [ ] Evidence captures the baseline and the decisive differential response.
