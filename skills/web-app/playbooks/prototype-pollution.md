# Prototype Pollution — Playbook

## Vulnerability Description

**OWASP:** A03:2021 — Injection (and API Security / Misconfiguration surfaces)
**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)

Prototype pollution is a JavaScript (Node.js) vulnerability where an attacker controls a
property key such as `__proto__`, `prototype`, or `constructor.prototype` in a payload
that is merged/recursively assigned into an application object. Because behaviour is often
gated on object attributes (`isAdmin`, `role`, `status`, `auth`, default-option flags),
polluting the prototype can change application behaviour, enable privilege escalation, or
lead to XSS/RCE depending on downstream consumers. It most often appears in JSON body
parsers, object-merge utilities, and `query`/`body`→config mapping.

---

## Types

| Type | Description | Detection Method |
|---|---|---|
| **`__proto__` pollution** | Classic key set by JSON merge | submit `{"__proto__":{...}}` in a JSON body |
| **`constructor.prototype` pollution** | Alternative key path past frameworks that strip `__proto__` | submit `{"constructor":{"prototype":{...}}}` |
| **Reflected prototype** | Polluted attribute is echoed in the response | set a polluting key, see it reflected as a top-level field |
| **Blind behavioural** | No echo — infer via downstream behaviour change (admin flag, settings) | set `{role/status/isAdmin}` and re-check authorization |

---

## Detection

### Manual Payloads

```json
// JSON body to an update / create / search / config endpoint
{"name":"valid","email":"a@b.co","__proto__":{"role":"admin","isAdmin":true,"status":"admin"}}
{"constructor":{"prototype":{"role":"admin"}}}
{"name":"x","__proto__":{"polluted":true}}
```

```bash
# Probe an endpoint that reflects request JSON back
curl -s 'https://target.com/api/object' -X POST -H 'Content-Type: application/json' \
  -d '{"name":"probe","__proto__":{"polluted_violin":true}}'

# If the response or a later GET reflects the polluting key, the merge is unsafe.
# Watch for: response containing "polluted_violin" OR a top-level key change
# in an object that lists user attributes.
```

### Testing Locations
- JSON `PUT`/`POST` update/create endpoints (user profile, settings, cart items)
- Object-merge driven features: bulk update, import, config-override endpoints
- Query→config mapping (e.g. an endpoint that reads query params into a settings object)
- Any endpoint whose request body is reflected into a response object

### Behavioural confirmation
If a role/status/admin key is accepted through `__proto__`, verify authorization with a
read-only endpoint (e.g. an admin-only list) **without performing destructive writes**.
Prove the attribute was adopted, do not abuse it to change real data.

---

## Tools

| Tool | Purpose | Notes |
|---|---|---|
| **curl** | Primary manual payload delivery | JSON body with `__proto__` key |
| **Burp Repeater** | Iterate key paths and compare responses | via the in-scope HTTP proxy |
| **Node REPL** | Locally validate how a JSON merge would behave offline | not against the target |
| **jq** | Inspect response JSON for polluting keys | `... | jq '.. | objects | .__proto__'` |

---

## Internet Research

- `<product> prototype pollution`
- `prototype pollution via __proto__`
- `CLIENT-SIDE prototype pollution (CWE-1321)`
- `site:portswigger.net prototype pollution`
- `Ghost CMS prototype pollution` (canonical public example) / `<product> CVE`

---

## Safe Proof of Concept

```json
// Use an inert marker key so the proof is observable but non-destructive
{"__proto__":{"violin_probe":true}}
{"constructor":{"prototype":{"violin_probe":true}}}
```

```bash
# 1) Submit the probe key in a JSON body
# 2) Request the same object back (GET/PUT echo) and check whether violin_probe is present
# 3) If present -> the merge is unsafe; record it. Do NOT set role/isAdmin to real values
#    unless separately authorized, and never use it to modify data.
```

Proof-of-concept rules:
- Prefer an inert marker key (`violin_probe: true`) over a behaviour-altering key.
- Never use a polluted `isAdmin`/`role` to perform write operations.
- If you must prove behaviour (e.g. admin access), use a read-only admin list and re-verify
  with a baseline unauthenticated request.
- Never pollute `env`/`child_process`-adjacent keys that could lead to RCE.

---

## Evidence

Each finding should include:

```
Vulnerability: Prototype Pollution (client/object-merge)
URL: https://target.com/api/profile
Method: PUT / body: application/json
Payload: {"name":"probe","__proto__":{"violin_probe":true}}

HTTP Request:
  PUT /api/profile HTTP/1.1
  Host: target.com
  Authorization: Bearer <token>
  {"name":"probe","__proto__":{"violin_probe":true}}

Response:
  HTTP/1.1 200 OK
  {"name":"probe","email":"...","violin_probe":true, ...}

Proof: the nested "__proto__" key was merged into the returned user object
(violin_probe reflected), demonstrating an unsafe recursive merge of
client-controlled JSON.
Remediation: recursively assign without copying prototype keys; use
Object.create(null) / a merge lib that blocks __proto__; reject "__proto__",
"constructor", "prototype" keys; freeze Object.prototype in the app bootstrap.
```

---

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/prototype-pollution/<finding>.*`
- Request/response pairs → `$ENG_DIR/evidence/exploitation/http/`
- Screenshots (if applicable) → `$ENG_DIR/evidence/exploitation/screenshots/`

---

## Remediation

| Measure | Description |
|---|---|
| **Block dangerous keys** | Reject `__proto__`, `prototype`, `constructor` in parsed JSON / merge input |
| **Safe merge** | Use `Object.create(null)` for parsed objects, or a merge fn that skips prototype keys |
| **Freeze prototypes** | `Object.freeze(Object.prototype)` at app bootstrap as defense-in-depth |
| **Schema validation** | Whitelist known fields in update/create endpoints |
| **Use `JSON.parse` with a reviver** | Drop keys matching the dangerous set during parsing |
| **Least privilege on attribute checks** | Do not gate authorization on client-controllable object attributes |

---

## Stop Conditions

- Pollution leads to a privilege change on a real account → stop, record, request separate authorisation for further proof.
- A polluting payload appears to enable RCE (e.g. via template/expression eval) → halt immediately and reassess.

## Blocked Actions

| Action | Risk |
|---|---|
| **Polluting to escalate a real account's privileges** | Unauthorized access |
| **Polluting `env` / child_process / eval-adjacent keys** | Remote code execution |
| **Using polluted defaults to tamper with other users' objects** | Data integrity |
| **Persisting hostile prototypes across the test** | Application breakage |
| **Reading secrets via a polluted object elsewhere in the application** | Data exfiltration |