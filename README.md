# Violin

Violin is a supervised Hermes profile for authorized penetration testing. It
provides a guarded execution boundary, engagement state, routed security
playbooks, evidence capture, and report generation.

```bash
hermes profile install https://github.com/Strategic-Automation/violin
hermes -p violin
```

## Requirements

- Python 3.11
- Hermes Agent 0.18.0 or newer
- `uv` for development and release checks
- Kali Linux or Parrot OS for the expected security-tool environment
- Written authorization and an approved scope before target interaction

The profile currently declares `tencent/hy3:free` through the Nous provider as
its default model. Operators can change the model through their Hermes
configuration.

## Engagement workflow

1. Initialize the engagement and approve `scope/scope.yaml`.
2. Select one active PTT task and its routed skill with
   `violin_record_ptt`.
3. Run target commands with `violin_exec` or `violin_exec_burst`.
4. Record hypotheses as evidence changes their status.
5. Review each bounded command batch with `violin_review_batch`.
6. Generate canonical findings and the final report.
7. Complete the retrospective.

The phase model is:

`SCOPING` → `RECON` → `VULN_RESEARCH` → `EXPLOITATION` → optional
`POST_EXPLOITATION`, `PRIVESC`, or `FLAGS` → `REPORTING` → `RETROSPECTIVE`.

Starting work in a new phase requires a PTT task under that phase. Existing
tasks are not moved between phase sections.

## Guard tools

The plugin registers these Hermes tools:

| Tool | Purpose |
|---|---|
| `violin_record_ptt` | Create, start, refresh, close, or cancel a PTT task |
| `violin_record_hypothesis` | Create or update a scoped hypothesis |
| `violin_exec` | Execute one guarded command |
| `violin_exec_burst` | Execute a bounded newline-delimited command batch |
| `violin_exec_status` | Read background execution status |
| `violin_exec_cancel` | Cancel tracked background execution |
| `violin_review_batch` | Review a completed batch and settle state |
| `violin_rebind_pending_batch` | Rebind a pending batch after explicit confirmation |
| `violin_heartbeat_done` | Clear a completed heartbeat review |
| `violin_target` | Resolve the approved assessment target |
| `violin_status` | Explain phase, task, skill, and synchronization blockers |

`violin_exec` is the only generic target-command boundary. There are no
tool-specific execution adapters or binary allowlists. Installed
non-interactive tools may run only after scope, phase, PTT, skill, hypothesis,
history, and synchronization checks pass.

The plugin's raw-terminal hook is a best-effort safety net, not a substitute
for guarded execution. Use `terminal` only for host-local administration and
preparation.

## Required engagement files

`init-engagement` creates the canonical structure:

```text
$ENG_DIR/
├── scope/scope.yaml
├── state/ptt.md
├── state/history.md
├── state/checkpoint.json
├── hypotheses.md
├── evidence/
├── reporting/
└── retrospective/
```

Raw evidence belongs under `$ENG_DIR/evidence/<phase>/`. State files contain
workflow state, not raw scanner output, tokens, or proof dumps.

## Skill delivery

Skills are loaded on demand. The first `violin_record_ptt` call for a routed
skill may return `skill_prepared` without changing the PTT. After Hermes
delivers the skill content, repeat the same transition to bind the receipt and
apply the task change. Use `violin_status` for the exact recovery action.

Do not create `.skill-loaded-*` marker files. They do not prove skill delivery.

## Safety rules

- Do not interact with a target before scope approval and bootstrap checks.
- Do not use raw shell execution for target commands.
- Do not perform destructive, disruptive, credential, persistence, stealth,
  or third-party actions without explicit written authorization.
- Keep proof minimal and reproducible.
- Redact credentials, tokens, and unrelated personal data from chat and state.
- Continue in the current Hermes conversation after context compression and
  restore state from `$ENG_DIR/state/`.

The detailed policy is in
[`skills/pentest/references/standards.md`](skills/pentest/references/standards.md).

## Administrative CLI

The standalone CLI is for bootstrap, diagnostics, recovery, closeout, and
release verification. Target execution remains a plugin responsibility.

```bash
python scripts/violin_guard.py --help
python scripts/violin_guard.py init-engagement engagements/example --host example.com
python scripts/violin_guard.py check-bootstrap --eng-dir engagements/example
python scripts/violin_guard.py status --eng-dir engagements/example
python scripts/violin_guard.py check-release
```

`check-command` exposes the same admission checks for diagnostics. It does not
execute the command.

## Repository layout

```text
benchmark/                  benchmark runner, scorer, proof checks, fixtures
docs/BENCHMARKS.md          benchmark methodology and verification limits
plugins/violin_guard/
  core/                     state, schemas, parsing, phase and target models
  gates/                    command, scope, hypothesis and terminal policies
  engine/                   execution and release verification
  handlers/                 public Hermes tool handlers
  hooks.py                  Hermes lifecycle hooks
  registry.py               registered tool definitions
scripts/                    administrative CLI and platform smoke tests
skills/                     orchestrator, routed skills, playbooks, references
tests/                      runtime, integration, documentation and release tests
```

## Benchmarks

The repository includes the Escape Duck Store target definition and known-good
and known-bad scorer fixtures. Calibration proves only that the scorer handles
those fixtures; it does not establish live-agent recall or report quality.

```bash
uv run python benchmark/score.py --calibrate known-good
uv run python benchmark/score.py --calibrate known-bad
uv run python -m benchmark.run --target https://duck-store.escape.tech
```

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) before publishing a score.

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python scripts/violin_guard.py check-release
```

The release gate checks version surfaces, plugin import and registration,
generated schemas, skill snapshots, stale documentation references, Ruff, and
the full test suite.

Platform smoke tests are available as `scripts/smoke-test.sh` and
`scripts/smoke-test.ps1`. The PowerShell smoke covers bootstrap, scope, and
target resolution; skill delivery and target execution require Hermes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).
