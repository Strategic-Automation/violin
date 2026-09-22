# Contributing to Violin

Thanks for your interest in Violin — the supervised agentic Hermes pentest profile.

## How to Contribute

### Creating Issues

Use the repository's structured issue forms:

- **Bug Report** for reproducible defects.
- **Feature Request** for new capabilities or workflow behaviour.
- **Engineering Task** for refactors, research, maintenance, documentation, CI, or testing work.

Before opening an issue, search open and closed issues and open pull requests for overlapping
work. Keep one independently reviewable concern per issue.

Issue titles should be clean, descriptive summaries. Do not add priority, order, type, or
status prefixes. Use GitHub-native issue types, project fields, dependencies, sub-issues,
milestones, and area labels where available.

See [the issue standards](.github/ISSUE_STANDARDS.md) for the canonical structure and metadata
rules. Security vulnerabilities in Violin itself must be reported through
[SECURITY.md](SECURITY.md), not a public issue.

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
5. Open a pull request against `dev`:
   - Title: Conventional Commits format — `type(scope): lowercase summary` with
     no trailing period. Types: `feat fix refactor perf test docs chore ci style
     revert build release`. CI checks every title.
   - Description: fill in `PULL_REQUEST_TEMPLATE.md` (Summary and Verification
     are required; CI checks this too). Link the issue you close with
     `Fixes #123` on its own line.
   - Area labels (guard, playbooks, benchmark, docs, ci, tests, packaging) are
     applied automatically; add others by hand where useful.
   - Feature branches are squash-merged; release PRs merge with a merge commit.

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
