# Strategic-Automation/violin — AI Developer Guidance

Workspace developer guidance for AI coding agents (Antigravity, Hermes, Codex, Cursor) developing or maintaining `violin`.

## 1. Stack & Setup
- **Python:** 3.11 (`.python-version`, `pyproject.toml`)
- **Package Manager:** `uv` (`uv sync --dev`)
- **Venv:** `.venv` via `uv`

## 2. Mandatory Verification Commands
Run before declaring completion:
```bash
uv run pytest                                # Full test suite (100% pass)
uv run ruff check .                          # Linter check
uv run ruff format --check .                 # Format check (fix: uv run ruff format .)
uv run python scripts/violin_guard.py check-release # Release gate check
```

## 3. Code Conventions & Architecture
- **Hermes Runtime Contract:** Target-touching CLI commands MUST use `plugins.violin_guard` typed tools (`violin_exec`, `violin_record_ptt`, `violin_review_batch`, `violin_record_hypothesis`, `violin_target`, `violin_status`, `violin_listener`). Never invoke flat CLI scripts (`python violin_guard.py`).
- **Fail-Closed Validation:** State parsers (`hypotheses.py`, `ptt.py`, `command.py`, `targets.py`) validate inputs fail-closed before mutating state.
- **Section Preservation:** Rewriters (`_rewrite_hypotheses`, `update_task`) MUST preserve template sections (`## Observations`, `## Decoy Trail`, `## Research Log`, `## Resolved Theories`, table columns). Never manually overwrite `hypotheses.md` with unstructured narrative text; keep canonical `### H-XXX:` blocks and status fields intact.
- **Evidence Path Isolation:** Save all raw evidence, dumps, tokens, and PoC outputs strictly under `$ENG_DIR/evidence/<phase>/`. Never place evidence files inside `$ENG_DIR/state/` (reserved for runtime state tracking).
- **Typed Schemas:** Use Pydantic v2 `BaseModel` models in `plugins/violin_guard/schemas.py`.
- **Encoding:** Explicit `encoding="utf-8"` required for all text file operations.

## 4. Git & Branching Strategy
- **Branches:** `codex/<topic>` or `dev`
- **Flow:** `codex/<topic>` ──► `dev` ──► PR to `master` (`master` protected by `GH013`).

## 5. Hard Boundaries
1. **NEVER Bypass Target Execution Guards:** No raw shell execution for target commands.
2. **NEVER Swallow Exceptions or Patch Tests Superficialy:** Fix root causes; never mask errors or alter assertions.
3. **NEVER Hardcode Target IPs:** Resolve via `violin_target` or `scope.yaml`.
4. **NEVER Declare Success Without Empirical Verification:** Always run `uv run pytest` and `uv run ruff check .`.
