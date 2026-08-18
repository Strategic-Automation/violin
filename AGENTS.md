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
- **Hermes Runtime Contract:** Target-touching CLI commands MUST use `plugins.violin_guard` typed tools (`violin_exec`, `violin_record_ptt`, `violin_review_batch`, `violin_record_hypothesis`, `violin_target`, `violin_status`). Never invoke flat CLI scripts (`python violin_guard.py`).
- **Fail-Closed Validation:** State parsers (`hypotheses.py`, `ptt.py`, `command.py`, `targets.py`) validate inputs fail-closed before mutating state.
- **Section Preservation:** Rewriters (`_rewrite_hypotheses`, `update_task`) MUST preserve template sections (`## Observations`, `## Decoy Trail`, `## Research Log`, `## Resolved Theories`, table columns). Never manually overwrite `hypotheses.md` with unstructured narrative text; keep canonical `### H-XXX:` blocks and status fields intact.
- **Evidence Path Isolation:** Save all raw evidence, dumps, tokens, and PoC outputs strictly under `$ENG_DIR/evidence/<phase>/`. Never place evidence files inside `$ENG_DIR/state/` (reserved for runtime state tracking).
- **Typed Schemas:** Use Pydantic v2 `BaseModel` models in `plugins/violin_guard/schemas.py`.
- **Encoding:** Explicit `encoding="utf-8"` required for all text file operations.
- **Library-First Development:** Always use libraries—both Python standard library (e.g., `functools.lru_cache`, `dataclasses`, `pathlib`, `contextlib`, `ipaddress`, `argparse`, `datetime.timedelta`, `shutil`, `re`, `shlex`, `hashlib`) and declared external dependencies (`pydantic`, `netaddr`, `yarl`, `filelock`, `pyyaml`, `bashlex`, `psutil`)—instead of rolling custom code or manual parsing algorithms. Always check if existing built-in or project dependencies provide the required functionality before writing custom implementations.
- **Spelling & Naming:** Use American English throughout codebase symbols and exports (`normalize_target`, `serialize`, `initialize`). Avoid single-letter variable names (`a`, `r`) in public/internal handler signatures and function definitions.
- **Timestamp Standardisation:** Use ISO-8601 UTC formats (`datetime.now(UTC).isoformat()`) across all state, receipt, and evidence timestamps.
- **Process & Concurrency Safety:** Never mutate global process environment (`os.environ`) in request handlers or adapter logic; pass parameters explicitly. Always acquire advisory locks (`lock_file` / `workflow_lock`) before writing to or appending to any state/feedback files.
- **No Test Artifact Leakage in Production:** Production code must NEVER inspect `sys.modules` for test-specific package names or test-specific shims. Use clean dependency injection, fixtures, or `unittest.mock`.
- **Domain-Driven Test Naming:** Name test files and test functions descriptively after the capability, invariant, or subsystem under test (e.g., `test_batch_integrity.py`), never after transient ticket numbers (`task1`, `a1-a15`) or static version numbers (`roadmap_1_1_1`).

## 4. Git & Branching Strategy
- **Branches:** `codex/<topic>` or `dev`
- **Flow:** `codex/<topic>` ──► `dev` ──► PR to `master` (`master` protected by `GH013`).
- **Commit Conventions:** Follow Conventional Commits (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`). Use imperative mood, lowercase types, and no trailing periods. Ensure clean rebasing without duplicate dual-author cherry-picks.

## 5. Hard Boundaries
1. **NEVER Bypass Target Execution Guards:** No raw shell execution for target commands.
2. **NEVER Swallow Exceptions or Patch Tests Superficially:** Fix root causes; never mask errors or alter assertions (no bare `except Exception: pass`).
3. **NEVER Hardcode Target IPs:** Resolve via `violin_target` or `scope.yaml`.
4. **NEVER Reinvent Existing Library Functionality:** Always check for and use built-in standard library or installed project dependencies where viable instead of hand-rolling custom code.
5. **NEVER Declare Success Without Empirical Verification:** Always run `uv run pytest` and `uv run ruff check .`.
