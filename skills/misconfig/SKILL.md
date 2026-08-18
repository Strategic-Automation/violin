---
name: misconfig
description: "Test deployment, configuration, and observability weaknesses."
version: 0.1.0
author: Violin
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [pentest, misconfiguration, deployment, observability, headers]
    related_skills: [pentest, web-app]
---

# Configuration, Deployment, and Observability Testing

On-demand skill for weaknesses that arise from how an application is deployed and operated rather than from its code logic: security misconfiguration, information leakage via obscurity, and observability failures (missing logging, monitoring, and error-handling disclosure). It does not contain injection payloads.

## When to Use

- Verbose errors, default credentials, exposed management interfaces, or permissive headers/CORS are observed.
- A finding depends on deployment posture, hidden-but-guessable naming, or missing logging/monitoring.
- Do not use for injection, authz, API protocol, or workflow flaws; route those classes to the appropriate specialist skill.

## Playbook Routing

| Class | Playbook |
|---|---|
| Security misconfiguration | `playbooks/security-misconfiguration.md` |
| Security through obscurity | `playbooks/security-through-obscurity.md` |
| Observability failures | `playbooks/observability-failures.md` |

## Common Pitfalls

- Separate deployment posture from code defects; a misconfiguration is a configuration fix, not a code fix.
- Preserve the exact header, error body, or default credential as decisive evidence.
- Read the playbook stop conditions before probing management interfaces or default credentials.

## Verification Checklist

- [ ] Engagement bootstrap and scope validation succeeded.
- [ ] The matched playbook alone was loaded and bound to the PTT task.
- [ ] Evidence captures the exact misconfigured value or missing control.
