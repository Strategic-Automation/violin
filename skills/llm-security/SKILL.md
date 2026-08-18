---
name: llm-security
description: "Test LLM prompt injection and MCP tool/agent surfaces."
version: 0.1.0
author: Violin
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [pentest, llm, ai, prompt-injection, mcp, json-rpc]
    related_skills: [pentest, api-testing]
---

# LLM and Agent Security Testing

On-demand skill for AI/LLM application attack surfaces: prompt injection, jailbreaking, and Model Context Protocol (MCP) / JSON-RPC tool and resource exposure. It is distinct from REST/GraphQL API testing; MCP is an agent tool protocol, not a conventional API.

## When to Use

- A chatbot, recommendation, generation, or LLM-backed endpoint is in scope.
- A Model Context Protocol endpoint (`initialize`, `tools/list`, `tools/call`, `resources/read`) or JSON-RPC surface is discovered.
- Do not use for REST/GraphQL/SOAP inventory or authz; use `api-testing` for those, then route the confirmed class back to the right specialist playbook.

## Playbook Routing

| Class | Playbook |
|---|---|
| LLM prompt injection, jailbreak, indirect injection | `playbooks/llm-prompt-injection.md` |
| MCP / JSON-RPC tool, resource, and session testing | `playbooks/mcp-api-testing.md` |

## Common Pitfalls

- Identify the LLM integration and the tool/resource surface before injecting.
- Keep probes read-only and reversible; do not extract or exfiltrate production secrets beyond what proves the flaw.
- Treat a tool that is callable without its expected authorization as a broken-access-control candidate, not merely a protocol finding.

## Verification Checklist

- [ ] Engagement bootstrap and scope validation succeeded.
- [ ] The matched playbook alone was loaded and bound to the PTT task.
- [ ] Evidence captures the injected payload, the decisive response, and the intended versus observed behavior.
