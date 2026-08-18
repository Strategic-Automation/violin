---
name: api-testing
description: "Test REST, GraphQL, SOAP, and WebSocket API surfaces."
version: 0.1.0
author: Violin
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [pentest, api, graphql, websocket, rest, soap]
    related_skills: [pentest, identity-auth, web-app, business-logic, llm-security]
---

# API Security Testing

On-demand skill for API protocol, inventory, schema, and machine-to-machine attack surfaces. It covers REST, GraphQL, SOAP, and WebSocket endpoints; load the targeted playbook rather than treating APIs as ordinary web routes. Model Context Protocol (MCP) surfaces route to `llm-security`.

## When to Use

- OpenAPI/Swagger, GraphQL, SOAP, or WebSocket endpoints are discovered or in scope.
- The assessment needs endpoint inventory, version/legacy discovery, protocol-specific authorization checks, or schema-driven testing.
- Do not use this as a substitute for a dedicated root-cause playbook (for example IDOR, JWT, SSRF, or SQLi); route and load that playbook after API discovery identifies the class.

## Playbook Routing

| Surface | Playbook |
|---|---|
| REST / SOAP / GraphQL / WebSocket API security | `playbooks/api-security.md` |

## Common Pitfalls

- Inventory versions, undocumented endpoints, methods, schemas, and authentication contexts before fuzzing.
- Preserve full request/response pairs and protocol headers, including negotiated sessions.
- Keep rate, depth, batching, and streaming probes within the approved RoE.

## Verification Checklist

- [ ] Engagement bootstrap and scope validation succeeded.
- [ ] The API surface inventory identifies protocol, version, authentication, and schema sources.
- [ ] The root-cause playbook was loaded for every confirmed vulnerability class.
