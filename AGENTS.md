# Violin repository guidance

Violin is a supervised Hermes pentest profile. This file guides development and
maintenance of the directory tree containing it. Follow more specific AGENTS.md
files for their subtrees; direct system, developer, and user instructions take
precedence. Repository development is distinct from running an engagement.

## Start here

- Confirm the working directory, branch, base commit, and existing changes before
  editing. Preserve unrelated work. Keep review-only requests read-only.
- Run commands below from the project directory containing this file and
  `pyproject.toml`. In copied benchmark trees, Git may resolve to a parent checkout;
  do not mistake that parent's commit or clean status for the snapshot's identity.
- Use the Python version in `.python-version`, consistent with `requires-python`
  in `pyproject.toml` and the CI matrix. Resolve discrepancies before changing
  runtime versions; do not upgrade Python as an incidental documentation fix.
- Install development dependencies with `uv sync --dev`; use `uv run` and the
  project `.venv`. Keep dependency and lockfile updates intentional.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution conventions,
  [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for evaluation methodology, and
  [.github/workflows/ci.yml](.github/workflows/ci.yml) for automated checks.
  Keep this guidance aligned with those files when workflows change.

## Where changes belong

- `plugins/violin_guard/`: Hermes tools, schemas, execution gates, and state.
- `scripts/`: administrative CLI, smoke checks, and maintenance helpers.
- `skills/`: routed skills and domain playbooks; shared templates and references
  remain under `skills/pentest/`. Follow the routing map in `CONTRIBUTING.md`.
- `benchmark/`: runner, host-side evaluator, calibration, and aggregation.
- `tests/`: guard, benchmark, CLI, and documentation contract tests.

Prefer the smallest cohesive change. Reuse existing project helpers, the standard
library, and declared dependencies before adding custom parsing or abstractions.
Do not add wrappers or split modules without a concrete maintenance benefit.

## Testing and completion

During development, run the affected tests first, for example:

```text
uv run pytest tests/guard/integration/test_plugin_import_correctness.py -q
uv run pytest tests/benchmark -q
uv run pytest tests/pentest_docs -q
```

Add regression tests for changed behavior: reproduce the defect, exercise the
public boundary, and verify observable outcomes. For guards and state changes,
cover malformed inputs, rejection before mutation, and relevant retry/concurrency
cases. Use temporary directories and fixtures; avoid live targets in unit tests.
Use dependency injection or mocks for external boundaries, never production
branches that detect test modules. Name tests after capabilities or invariants,
not ticket numbers or release versions.

Before declaring an edited tree verified or ready for merge, run all four checks
against the final tree, including for documentation-only changes:

```text
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python scripts/violin_guard.py check-release
```

- All required checks must exit successfully. Report skipped tests and their
  reasons; a skip is not a passing test. Do not hide failures, weaken assertions,
  or add exclusions to obtain green output. Update expectations only when the
  intended behavior changes, and explain that change.
- Format changed Python files with `uv run ruff format <path>` when needed.
  Avoid unrelated formatting changes.
- `check-release` validates isolated plugin loading, registered tool/schema
  consistency, release surfaces, and skill references/snapshots. It also runs
  Ruff and pytest by default. CI's `VIOLIN_CHECK_RELEASE_SKIP_HEAVY=1` only avoids
  repeating separately executed checks; it is not permission to omit them.
- For administrative bootstrap/CLI changes, also run
  `pwsh -File scripts/smoke-test.ps1` on Windows. On Unix, use
  `uv run bash scripts/smoke-test.sh --no-install` for structural checks; the
  full script also installs a temporary Hermes profile and invokes a model,
  so use it for packaging/runtime validation with configured prerequisites.
  These smoke checks do not validate live target execution.
- CI tests Ubuntu and Windows. Local success on one OS does not prove both passed.
  For Windows cache/temp permission problems, use a writable uv cache and a fresh
  pytest `--basetemp` under an ignored directory with `-p no:cacheprovider`;
  create its parent directory first.
- Report commands, results, relevant skips, and any unavailable checks. A blocked
  environment is a verification limitation, not evidence of success. Recheck the
  final diff for whitespace errors, unrelated changes, secrets, and artifacts.

## Benchmarking before merge

Benchmark evidence is a merge requirement in addition to the checks above.
The two tiers answer different questions:

1. **Every PR:** run `uv run pytest tests/benchmark -q` and both scorer fixtures:

   ```text
   uv run python -m benchmark.score --calibrate known-good
   uv run python -m benchmark.score --calibrate known-bad
   ```

   Known-good must match all golden cases; known-bad must receive zero credit.
   Both commands should exit successfully for their expected outcomes.
2. **Runtime or evaluation changes, and releases:** complete live Hermes
   benchmarks before merging changes to guards, execution, findings/receipts,
   prompts, skills/playbooks, model/runtime configuration, packaging that affects
   runtime behavior, or the runner/evaluator. For documentation-only or other
   changes with no runtime/evaluation effect, record why live benchmarking is
   not applicable in the PR. Instructions consumed by the pentest agent are
   runtime behavior, even when written in Markdown.

Follow [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Inspect available options with
`uv run python -m benchmark.run --help`. The following single-line template works
in PowerShell and Bash after replacing the quoted placeholders:

```text
uv run python -m benchmark.run --target "<authorized-local-target-url>" --provider "<provider>" --api-base "<api-base-url>" --model "<model-id>" --target-isolation-id "<immutable-image-digest-or-reset-id>"
```

- Use an authorized isolated target, reset between independent runs, and pin the
  target identity, source revision, runtime image, model/provider, and settings.
  Never rely on the runner's default hosted target for merge evidence.
- Compare the candidate with its `dev` baseline under the same conditions. Use
  at least three independent runs per revision; report all runs and failures,
  mean pass@1, variation, pass@k/pass^k, and per-case regressions. Use
  `benchmark.aggregate` with an explicit glob per revision; never mix baselines,
  candidates, or incompatible protocols in one aggregate.
- Require valid runner completion and completed host evaluation. Inspect
  `benchmark_pass` in the results, not only the process exit code. The current
  scorer requires at least 85% confirmed findings, complete coverage and
  methodology, and a comparable protocol. Do not lower thresholds or change
  proof rules merely to make a candidate pass. Investigate failures and
  regressions before calling the change merge-ready; do not select only a best
  run or treat aggregate union coverage as a passing individual run.
- Keep evaluator golden data, matchers, and calibration fixtures out of the
  agent runtime. Credit requires authenticated receipts and decisive proof;
  finding prose, checklist completion, and demonstration scores are separate.
- Attach sanitized summaries or access-controlled artifact links to the PR,
  identifying baseline/candidate revisions, configuration, run count, scores,
  failures, and regressions. Keep credentials and raw engagement evidence out
  of Git and public PRs/issues. Publishable comparisons require a clean source
  tree and the pinned comparison protocol described in `docs/BENCHMARKS.md`.
- [.github/workflows/benchmark.yml](.github/workflows/benchmark.yml) is manually
  dispatched; ordinary CI runs deterministic tests. A green CI run, calibration,
  dry run, missing-Hermes fallback, or skipped live job does not satisfy a live
  benchmark requirement. If prerequisites are missing, report the blocker and
  leave live validation pending. These instructions do not by themselves add
  a required GitHub status check or authorize arbitrary external targets.

## Runtime and data invariants

- Target-touching commands must use registered Hermes Guard tools, including
  `violin_exec` / `violin_exec_burst`, with scope and approval gates intact.
  The standalone CLI is for administration and diagnostics. Normal local
  development commands above are not target execution.
- Resolve engagement targets through `violin_target` or `scope.yaml`; do not
  embed operational target IPs. Synthetic test fixtures remain isolated.
- Validate state and commands fail-closed before mutation or execution. Use
  Pydantic v2 models in `plugins/violin_guard/core/schemas.py` for tool contracts;
  keep registrations and `plugin.yaml` consistent.
- Acquire the existing advisory lock (`lock_file` / `workflow_lock`) before
  state/feedback writes, and use existing atomic-write helpers where applicable.
  Pass environment overrides to child processes explicitly; never mutate global
  `os.environ` in request handlers or adapters.
- Preserve canonical hypothesis blocks, status fields, table columns, and all
  template sections during Markdown rewrites, including Observations, Decoy
  Trail, Research Log, and Resolved Theories. Never replace structured hypothesis
  state with an unstructured narrative.
- Save raw engagement evidence under `$ENG_DIR/evidence/<phase>/`; `state/` is
  reserved for runtime tracking. Preserve tool-managed paths such as
  `evidence/executions/` and `evidence/findings.jsonl`. Declare file-based proof
  with `violin_exec.evidence_outputs` and cite authenticated receipts and
  evidence paths through `violin_submit_finding`.
- Use explicit UTF-8 for text file I/O, ISO-8601 UTC timestamps via
  `datetime.now(UTC).isoformat()`, American English symbols, and descriptive
  parameter names. Never silently swallow exceptions.

## Pull requests, releases, and issues

- Start feature work from current `dev` on `codex/<topic>`; preserve in-progress
  work when choosing a checkout. Feature PRs target `dev` and are squash-merged.
  Delete the topic branch only after confirming its merge.
- Use Conventional Commit titles as specified in `CONTRIBUTING.md`, with a
  lowercase summary and no trailing period. Fill in
  [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md), including
  Summary, Verification, benchmark evidence/applicability, and relevant issues.
- Before merge, verify required CI checks and reviews on the current PR revision,
  resolve conflicts, and refresh affected verification when the candidate changes.
  A local check or earlier commit's benchmark does not certify later changes.
- New playbooks require Evidence, Stop Conditions, and Blocked Actions sections.
  Update routing and README layout when adding skills. Keep user-facing docs,
  `distribution.yaml`, version surfaces, and `skills.snapshot.json` synchronized
  when the change affects them; do not invent release bumps for unrelated work.
- Release only through `dev` to `master` using **Create a merge commit**, never
  squash or rebase. Verify branch ancestry and shipped issue references first.
  After merge, verify release CI, tag/release, and the fast-forward dev-sync
  workflow. If sync fails due to divergence, inspect the graph and merge
  `master` back into `dev`; never force-push protected shared branches.
- Follow [.github/ISSUE_STANDARDS.md](.github/ISSUE_STANDARDS.md) for every created
  or edited issue. Search open/closed issues and open PRs first; keep one
  reviewable concern, native metadata/dependencies, testable acceptance criteria,
  and existing evidence/decisions. Report undisclosed Violin vulnerabilities
  privately as described in [SECURITY.md](SECURITY.md).
