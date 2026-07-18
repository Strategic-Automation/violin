# Contributing to Violin

Thanks for your interest in Violin — the supervised agentic Hermes pentest profile.

## How to Contribute

### Reporting Bugs

1. Check the [issues](https://github.com/Strategic-Automation/violin/issues) for duplicates
2. Include: Violin version, Hermes version, OS/platform, steps to reproduce, and any guard output
3. Use the bug report template if available

### Requesting Features

1. Open a feature request issue describing the playbook, vulnerability class, or workflow you'd like added
2. Explain the use case and how it fits Violin's supervised, authorised testing paradigm
3. Include references to OWASP, PTES, or NIST methodology if applicable

### Submitting Changes

1. Fork the repo and create a feature branch from `master`
2. Follow the existing file structure and conventions:
   - Engagement phases and shared vulnerability playbooks go in `skills/pentest/playbooks/`
   - Injection/web playbooks go in `skills/web-attacks/playbooks/`
   - Authentication and authorisation playbooks go in `skills/access-control/playbooks/`
   - Shared references and templates stay in `skills/pentest/references/` and `skills/pentest/templates/`
   - Hermes guard implementation belongs in `plugins/violin_guard/`; `scripts/` contains CLI and smoke helpers
   - A new routed skill requires its own `skills/<name>/SKILL.md` and an update to the pentest orchestrator and README layout
3. If adding a new playbook, ensure it has `## Evidence`, `## Stop Conditions`, and `## Blocked Actions` sections
4. Run `python scripts/violin_guard.py check-release` before opening a PR
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

- Python: `ruff`-compatible, type hints where practical
- Shell: `bash` with `set -euo pipefail`, POSIX-compatible where possible
- Markdown: standard GFM, 80-char soft wrap for prose
- YAML: valid, safely parseable YAML; preserve the existing schema's key style (for example `rules_of_engagement` and `allowed_actions`)

## Code of Conduct

Be respectful, constructive, and assume good faith. This is a security tool — our goal is safer systems, not causing harm.
