---
name: identity-auth
description: "Test identity, authentication, authorization, and sessions."
version: 2.0.0
author: Violin
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [pentest, identity, authentication, authorization, session]
    related_skills: [pentest, web-app, api-testing]
---

# Identity, Authentication, and Authorization Testing

On-demand skill for identity-management, authentication, authorization, session, and cryptographic-control testing. The `pentest` orchestrator routes here when a finding candidate crosses an identity or authorization boundary. Load only the applicable playbook.

## When to Use

- A login, registration, password-reset, MFA, session, token, role, or object-ownership boundary is in scope.
- Multiple users or privilege levels are available for differential testing.
- Do not use for general API inventory or business workflow flaws unless an identity boundary is the root cause.

## Playbook Routing

| Class | Playbook |
|---|---|
| Authentication Bypass | `playbooks/auth-bypass.md` |
| IDOR / Broken Object-Level Authorization | `playbooks/idor-access-control.md` |
| JWT / Token Attacks | `playbooks/jwt-attacks.md` |
| CSRF | `playbooks/csrf.md` |
| Unvalidated Redirect | `playbooks/redirects-unvalidated.md` |
| Cryptographic Issues | `playbooks/cryptographic-issues.md` |

## Common Pitfalls

- Use authorized disposable accounts and compare unauthenticated, low-privilege, and authorized contexts.
- Redact credentials, sessions, and token values in all artifacts.
- Treat a changed status code alone as a candidate; capture the protected resource or state differential needed to prove impact.

## Verification Checklist

- [ ] Engagement bootstrap and scope validation succeeded.
- [ ] The matched playbook alone was loaded and bound to the PTT task.
- [ ] Evidence includes the two relevant identity or authorization contexts.
