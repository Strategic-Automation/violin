---
name: business-logic
description: "Test workflows, state transitions, pricing, and concurrency."
version: 0.1.0
author: Violin
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [pentest, business-logic, workflow, race-condition, state]
    related_skills: [pentest, api-testing, identity-auth]
---

# Business Logic Security Testing

On-demand skill for application-specific rules and state transitions that technical vulnerability taxonomies do not fully describe. It owns the single canonical business-logic playbook; do not duplicate workflow, pricing, coupon, or race-condition procedures in other skills.

## When to Use

- An application has multi-step workflows, pricing, quotas, inventory, coupons, referrals, approvals, or state transitions.
- A candidate depends on violating an intended business rule rather than exploiting a parser or authorization check alone.
- Do not use for mass assignment, IDOR, or API inventory when those are the root cause; route to `api-testing` or `identity-auth` first.

## Playbook Routing

| Class | Playbook |
|---|---|
| Workflow bypass, pricing, coupon, quota, referral, or race-condition flaw | `playbooks/workflow-state-abuse.md` |

## Common Pitfalls

- Map the expected state machine and record a clean baseline before mutating a field or sequence.
- Prefer disposable accounts, preview endpoints, and reversible actions.
- Do not complete transactions, deplete stock, or alter third-party data without explicit approval.

## Verification Checklist

- [ ] Engagement bootstrap and scope validation succeeded.
- [ ] The expected workflow and attempted invalid transition are documented.
- [ ] Evidence shows the baseline, mutation, and resulting rule violation.
