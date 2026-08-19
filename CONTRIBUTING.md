# Contributing to Violin

Thanks for your interest in Violin — the supervised agentic Hermes pentest profile.

## How to Contribute

### Reporting Bugs

1. Check the [issues](https://github.com/Strategic-Automation/violin/issues) for duplicates
2. Include: Violin version, Hermes version, OS/platform, steps to reproduce, and any guard output
3. Use the bug report template if available

### Requesting Features

1. Open a feature request issue describing the playbook, vulnerability class, or workflow you'd like added
2. Explain the use case and how it fits Violin's supervised, authorized testing model
3. Include references to OWASP, PTES, or NIST methodology if applicable

### Submitting Changes

1. Fork the repo and create a feature branch from `dev`
2. Follow the existing file structure and conventions:
   - Engagement phases and shared vulnerability playbooks go in `skills/pentest/playbooks/`
   - Injection/client-side web playbooks go in `skills/web-app/playbooks/`
   - Identity, authentication, authorization, and session playbooks go in `skills/identity-auth/playbooks/`
   - API protocol playbooks go in `skills/api-testing/playbooks/`
   - Workflow, pricing, and state-transition playbooks go in `skills/business-logic/playbooks/`
   - LLM prompt-injection and MCP playbooks go in `skills/llm-security/playbooks/`
   - Deployment, configuration, and observability playbooks go in `skills/misconfig/playbooks/`
   - Shared references and templates stay in `skills/pentest/references/` and `skills/pentest/templates/`
   - Hermes guard implementation belongs in `plugins/violin_guard/`; `scripts/` contains CLI and smoke helpers
   - A new routed skill requires its own `skills/<name>/SKILL.md` and an update to the pentest orchestrator and README layout
3. If adding a new playbook, ensure it has `## Evidence`, `## Stop Conditions`, and `## Blocked Actions` sections
4. Run the required verification commands before opening a PR:

   ```bash
   uv run pytest
   uv run ruff check .
   uv run ruff format --check .
   uv run python scripts/violin_guard.py check-release
   ```
5. Open a pull request with a clear description of the change

### Playbook Standards

All vulnerability-class playbooks must:

- Reference the OWASP/PTES/CWE mapping in the title
- Include detection methods with concrete tool commands
- Specify safe PoC techniques (no destructive payloads)
- Define evidence file paths using `$ENG_DIR/evidence/exploitation/<playbook-name>/`
- List stop conditions and blocked actions
- Gracefully degrade if recommended tools are unavailable

### Code Style

- Python: Ruff-formatted, Pydantic v2 models for public tool schemas, and type
  hints where they clarify a contract
- Shell: `bash` with `set -euo pipefail`, POSIX-compatible where possible
- Markdown: standard GFM, 80-char soft wrap for prose
- YAML: valid, safely parseable YAML; preserve the existing schema's key style (for example `rules_of_engagement` and `allowed_actions`)
- Documentation: describe behavior enforced by the current code; avoid
  marketing claims, repeated warnings, speculative features, and stale command
  examples

## Code of Conduct

Be respectful, constructive, and assume good faith. This is a security tool — our goal is safer systems, not causing harm.
