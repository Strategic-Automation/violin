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
   - Playbooks go in `skills/pentest/playbooks/`
   - References in `skills/pentest/references/`
   - Templates in `skills/pentest/templates/`
   - Python scripts in `scripts/`
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
- YAML: anchors for repeated values, kebab-case for keys

## Code of Conduct

Be respectful, constructive, and assume good faith. This is a security tool — our goal is safer systems, not causing harm.