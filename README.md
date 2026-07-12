<p align="center">
  <img src="assets/logo.png" alt="Violin" width="256"/>
</p>

<h1 align="center">Violin ☤ — Supervised Agentic Hermes Pentest Profile</h1>

<p align="center">
  <a href="https://github.com/Strategic-Automation/violin"><img src="https://img.shields.io/badge/Status-Release%20Ready-2ea44f?style=for-the-badge" alt="Release Ready"></a>
  <a href="https://github.com/Strategic-Automation/violin/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License: MIT"></a>
  <a href="https://hermes-agent.nousresearch.com/"><img src="https://img.shields.io/badge/Hermes-%3E%3D0.18.0-FFD700?style=for-the-badge" alt="Hermes >= 0.18.0"></a>
  <a href="https://www.kali.org/"><img src="https://img.shields.io/badge/Kali%20Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" alt="Kali Linux"></a>
  <a href="https://www.parrotsec.org/"><img src="https://img.shields.io/badge/Parrot%20OS-2E8B57?style=for-the-badge" alt="Parrot OS"></a>
</p>

<p align="center">
  <b>31 playbooks · 8 references · 1 optional guard plugin · 0 brokers · Hermes-native</b>
</p>

Violin is a **Hermes-native agentic pentest profile** for supervised, authorised penetration tests — from reconnaissance through safe exploit validation to reporting. It uses Hermes' built-in toolsets, skill-based playbooks, an optional `violin-guard` plugin, and lightweight guard scripts. No extra API keys, no per-profile credentials, no lock-in.

```
hermes profile install https://github.com/Strategic-Automation/violin
hermes -p violin
```

---

## Features

<table>
<tr><td width="280"><b>🔬 31 Methodology Playbooks</b></td><td>7 methodology playbooks (6 phase: scoping, recon, vuln-research, exploitation, reporting, post-exploitation — plus a tools catalog) + 24 per-vulnerability-class playbooks covering OWASP Top 10, OWASP API Top 10, LLM Top 10, and beyond.</td></tr>
<tr><td><b>🛡️ Multi-Layer Safety</b></td><td>Interactive scoping (8 questions) → scope validation → guard check → approval gates — every target-touching command validated before execution.</td></tr>
<tr><td><b>🧠 Pentesting Task Tree</b></td><td>Structured artifact tracking every task via `[x]/[ ]/[~]` markers across phases, with command history and hypothesis linking.</td></tr>
<tr><td><b>🌐 Browser + Web Research</b></td><td>Browser toolset for website enumeration. Web toolset for CVE lookup, exploit search, and OSINT.</td></tr>
<tr><td><b>📋 Evidence-Driven Reporting</b></td><td>Reproducible evidence with screenshots, tool output, request/response pairs. CVSS 3.1 scoring + auto-patch remediation.</td></tr>
<tr><td><b>🔗 Hermes-Native</b></td><td>Inherits your existing Hermes provider/model. No extra API keys, no per-profile credentials, no lock-in.</td></tr>
</table>

---

## Quick Start

```bash
# 1. Install the profile
hermes profile install https://github.com/Strategic-Automation/violin

# 2. Start a session
hermes -p violin

# 3. Let Violin ask scoping questions, then run your test
> Run a pentest against example.com
```

<details>
<summary><b>Prerequisites</b></summary>

- **Hermes Agent >= 0.18.0** — installed and on your PATH
- **Hermes provider configured** — Violin inherits your normal Hermes provider/model
- **Kali Linux or Parrot OS recommended** — Docker Kali, WSL, macOS, Windows, and remote jump boxes also work

</details>

<details>
<summary><b>Set as default profile</b></summary>

```bash
hermes profile use violin
```

</details>

---

## Engagement Workflow

```mermaid
flowchart LR
    A["1. Scoping"] --> B["2. Recon"]
    B --> C["3. Vuln Research"]
    C --> D["4. Exploitation"]
    D --> E["5. Reporting"]
    E --> F["6. Retrospective"]
    
    A -.->|"clarify"| G("Approval Gate")
    B -.->|"guard check"| G
    C -.->|"guard check"| G
    D -.->|"clarify + guard"| G

    style A fill:#1a1a2e,stroke:#e94560,stroke-width:2px
    style B fill:#16213e,stroke:#0f3460,stroke-width:2px
    style C fill:#1a1a2e,stroke:#e94560,stroke-width:2px
    style D fill:#16213e,stroke:#0f3460,stroke-width:2px
    style E fill:#1a1a2e,stroke:#e94560,stroke-width:2px
    style F fill:#16213e,stroke:#0f3460,stroke-width:2px
    style G fill:#2d2d2d,stroke:#ffd700,stroke-width:2px
```

| Phase | Action | Safety Gate |
|-------|--------|-------------|
| **1. Scoping** | 8 questions via `clarify` | User approval |
| **2. Reconnaissance** | Passive OSINT → tech detection → active scanning | Guard + approval |
| **3. Vuln Research** | CVE lookup, exploit search, attack surface analysis | Guard check |
| **4. Exploitation** | Safe PoC validation per vulnerability class | Guard + user approval |
| **5. Reporting** | Evidence compilation, CVSS scoring, remediation | — |
| **6. Retrospective** | Gap analysis, playbook coverage update | Mandatory |

---

## Architecture

```mermaid
graph TB
    subgraph "Your Machine"
        HE["Hermes Agent"]
        VI["Violin Profile"]
        GUARD["violin_guard.py"]
    end
    
    subgraph "Violin Skills"
        SK["SKILL.md"]
        PB["31 Playbooks"]
        REF["8 References"]
        TEMP["6 Templates"]
    end
    
    subgraph "Hermes Built-in Tools"
        T["terminal"]
        W["web"]
        B["browser"]
        F["file"]
        CE["code_execution"]
        S["skills"]
        CL["clarify"]
        D["delegation"]
        V["vision"]
        TD["todo"]
        VG["violin_guard"]
    end
    
    LLM["Your LLM Provider"]
    
    HE -->|"hermes -p violin"| VI
    VI -->|"loads"| SK
    SK -->|"routes to"| PB
    HE -->|"calls"| T & W & B & F & CE & S & CL & D & V & TD & VG
    HE -->|"inherits"| LLM

    style HE fill:#2d2d2d,stroke:#ffd700,stroke-width:2px
    style VI fill:#1a1a2e,stroke:#e94560,stroke-width:2px
    style GUARD fill:#16213e,stroke:#0f3460,stroke-width:2px
```

### Enabled Toolsets

11 toolsets configured in `config.yaml` (`platform_toolsets.cli`): 10 built-in — `terminal`, `web`, `browser`, `file`, `code_execution`, `skills`, `todo`, `clarify`, `delegation`, `vision` — plus the `violin_guard` guard-plugin toolset.

### Conversation & Memory Isolation

- `memory.memory_enabled: false` — no global memory recall/write
- `memory.user_profile_enabled: false` — no global user profile access
- `session_search` available for cross-referencing past engagements on the same target
- Engagement continuity lives in project files (scope docs, evidence, reports)
- Start a fresh Hermes conversation per engagement to keep boundaries clean

---

## Safety Model

```mermaid
flowchart LR
    subgraph "Layer 1"
        A["8 Scoping Questions"]
        B["Written Authorisation"]
    end
    subgraph "Layer 2"
        C["violin_guard.py validate-scope"]
    end
    subgraph "Layer 3"
        D["violin_guard.py check-command"]
    end
    subgraph "Layer 4"
        E["clarify approval gate"]
    end
    subgraph "Layer 5"
        F["Standards & Blocked Actions"]
    end
    
    A --> B --> C --> D --> E --> F
```

- **Authorised testing only** — no probing before scoping is complete
- **Approval gates** — scope, active recon, and exploitation each require explicit user approval
- **Guard check** — every target-touching terminal command validated by `violin_guard.py` (exit 0=allowed, 1=blocked, 2=review)
- **Non-destructive by default** — exploitation limited to safe, reproducible PoC
- **Evidence-first** — every finding backed by reproducible tool output, screenshots, request/response pairs
- **Exploit-first validation** — no hypothesis advances to Validated without a verification command
- **Fresh context per objective** — structured state summaries on phase transitions to prevent context bloat

Full safety policy: `skills/pentest/references/standards.md`. Forbidden actions: `.hermes.md` §Forbidden Behaviour.

---

## Repository Layout

```
violin/
├── .hermes.md              # Project-level agent context
├── SOUL.md                 # Agent identity — senior pentester persona
├── config.yaml             # Profile config (toolsets, safety, memory)
├── distribution.yaml       # Hermes distribution manifest
├── scripts/                # Guard & smoke tests
│   ├── violin_guard.py     # CLI entrypoint for the guard state machine
│   └── guard/              # Guard logic: bootstrap, scope, command, record, sync, release
│   ├── smoke-test.sh       # Linux/macOS release smoke
│   ├── smoke-test.ps1      # Windows supplemental smoke
│   └── kali.sh             # Docker Kali helper
└── skills/pentest/         # Pentest methodology
    ├── SKILL.md            # Orchestrator skill (playbook index, workflow)
    ├── playbooks/          # 31 playbooks (7 phase + 24 vuln-class)
    ├── references/         # 8 reference documents
    └── templates/          # 6 templates (PTT, hypothesis board, scope, report, methodology gates, transparency boilerplate)
```

---

## Release Verification

```bash
python scripts/violin_guard.py check-release
```

Validates: YAML structure, 31 playbooks present, required sections in vuln playbooks, no stale evidence paths, all markdown references resolve.

---

## Optional: Kali Docker Container

<details>
<summary><b>One-time setup for a full Kali toolchain on any OS</b></summary>

See [`scripts/kali.sh`](scripts/kali.sh) for the container exec helper.

```bash
docker pull kalilinux/kali-rolling
docker create -it --name kali-pentest \
  -v /path/to/violin/engagements:/engagements \
  kalilinux/kali-rolling bash
docker start kali-pentest
docker exec kali-pentest apt update
docker exec kali-pentest apt install -y kali-linux-headless
```

</details>

---

## Optional MCP Servers

<details>
<summary><b>Enhance Violin with community MCP servers</b></summary>

| MCP Server | Install | Purpose |
|-----------|---------|---------|
| `onlinecybertools-mcp-server` | `npx -y onlinecybertools-mcp-server` | 280+ OSINT/recon tools — whois, SSL check, JWT decode, network diag, hashes |
| `runyourempire/4DA` | `npx -y @runyourempire/4DA` | Live CVE scanning, dependency health, upgrade planning |

Add to `config.yaml` under `mcp_servers:` after install. See [Hermes MCP docs](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp).

</details>

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR process, and code style.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

---

## License

MIT — see [LICENSE](LICENSE).