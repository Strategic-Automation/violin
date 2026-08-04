# Strategic-Automation/violin — AI Developer Guidance

> Workspace-scoped developer guidance for AI coding agents (Antigravity, Hermes, Codex, Cursor, etc.) developing, testing, or maintaining the `violin` codebase.
>
> *Note:* For deployed end-user Hermes pentest installations, runtime identity and engagement rules are packaged in `SOUL.md`, `.hermes.md`, and `skills/pentest/SKILL.md`. This file governs AI agent developer behavior within this repository workspace.

---

## 1. Stack & Environment Setup

- **Python Version:** 3.11 (pinned in `.python-version` and `pyproject.toml` to match Hermes runtime).
- **Package Manager:** `uv` (use `uv sync --dev` to sync development environment).
- **Virtual Environment:** `.venv` created and managed via `uv`.

---

## 2. Mandatory Verification Commands

Run these commands to verify any code changes before declaring completion:

```bash
# 1. Run full test suite (must pass 100%)
uv run pytest

# 2. Run linter check
uv run ruff check .

# 3. Check code formatting (fix with `uv run ruff format .`)
uv run ruff format --check .

# 4. Validate release gate
uv run python -m plugins.violin_guard.release
```

---

## 3. Code Conventions & Architecture

- **Hermes Runtime Contract:** All target-touching CLI command execution in Violin engagements MUST go through `plugins.violin_guard` typed Hermes tool calls (`violin_exec`, `violin_record_ptt`, `violin_review_batch`, `violin_record_hypothesis`, `violin_target`, `violin_status`, `violin_listener`). Never invoke flat CLI scripts (`python violin_guard.py`) as a substitute for typed tool calls.
- **Fail-Closed Validation:** All state parsers (`hypotheses.py`, `ptt.py`, `command.py`, `targets.py`) must validate inputs fail-closed before mutating filesystem state.
- **Section Preservation:** File rewriters (`_rewrite_hypotheses`, `update_task`) must preserve structural template sections (`## Observations`, `## Decoy Trail`, `## Research Log`, `## Resolved Theories`, table columns).
- **Typed Schemas:** Use Pydantic v2 `BaseModel` models in `plugins/violin_guard/schemas.py` for all tool parameter specifications.
- **File Encoding:** Always specify `encoding="utf-8"` explicitly for all text file read/write operations.

---

## 4. Git & Branching Strategy

- **Feature/Docs Branches:** Use `codex/<topic>` or `dev`.
- **Merge Flow:** `codex/<topic>` ──► `dev` ──► PR to `master`.
- **Master Branch:** `master` is protected by GitHub repository rules (`GH013`); production releases require a Pull Request.

---

## 5. Hard Boundaries (What AI Agents Must Never Do)

1. **NEVER Bypass Target Execution Guards:** Never run target-touching commands directly in raw shell without `violin_exec` or `violin_exec_burst`.
2. **NEVER Swallow Exceptions or Patch Tests Superficialy:** Fix underlying root causes; never mask errors, return dummy fallbacks, or comment out failing assertions.
3. **NEVER Hardcode Target IPs:** Resolve target hosts dynamically via `violin_target` or `scope.yaml`.
4. **NEVER Declare Success Without Empirical Verification:** Always run `uv run pytest` and `uv run ruff check .` to prove zero regressions before finishing work.
