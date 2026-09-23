# Changelog

## 3.3.4

### Fixed

- Reporting close: a command whose receipt authenticates the submitted findings satisfies the close even when it ran under `VULN_RESEARCH`, and the refusal names the exact command that would satisfy it.
- Evidence identity: a saved evidence file cited by more than one receipt stays verifiable while it holds a version that some signed receipt recorded, and a genuine authentication failure names both conflicting citations with a remedy. Submission and the close now share one rule instead of two independent checks.
- Hypothesis-to-finding check requires overlap with a finding's authenticated proof rather than a strict subset, so a hypothesis that records everything it investigated no longer blocks its own close.
- Report rendering lists declared evidence paths alongside receipt-authenticated proof, so the reported evidence matches what the finding declared.
- Hypothesis board: rewrites are confined to the records they own, so an update can no longer duplicate records or drop the template's field-format comment, and the integrity retry says which record and phase failed.
- Phase gate: a hypothesis recorded without an explicit phase is evaluated against the phase in effect on every path, rather than only when it is explicitly linked to a task.
- Task preconditions: the active-task requirement applies to target-touching execution only, so host-local analysis and verification still run after the last task closes, and the refusal names the remedy.
- Host-local guards: DOM-API-shaped text in a locally executed script is no longer read as a target literal, the heuristic that blocked local scripts for containing words such as `probe` is gone, and the guard's own read-only diagnostics are reachable from the raw terminal.
- Coverage: scoping bootstrap pre-keys the coverage matrix from the engagement's declared obligations, and the close gate and that seeding share one key validator, so a close no longer demands obligation keys the agent had to invent.
- Bursts: a malformed command list is rejected before admission and leaves no receipt behind.
- Guard friction rows are written to their own file, so a guard block can no longer invalidate a queued edit to the agent-maintained feedback table.
- The semantic anti-stuck lock keys on evidence novelty rather than the presence of cited evidence, so reviews that produce fresh findings no longer hold a lock.
- Findings: resubmitting the same vulnerability updates one record, folding in the union of receipts and evidence paths, and the read path applies the same identity rule.
- Tool arguments: the record tools accept a numeric confidence or port and normalise variant vulnerability-class spellings, and an unknown class is rejected with the accepted values listed.
- Messages and contracts: a proof without literal HTTP response bytes states that the finding still counts and how to remedy it; an execution record keeps the command the caller requested and notes an injected status-capture flag; the exec-burst description documents the session-binding rule and where the id is read; the skill-bind payload states when a repeat call is required.
- The tool registry serialises its argument-error payload instead of raising when a validator reports a value error.

## 3.3.3

### Added

- Close issues automatically when a pull request that claims them merges into `dev`: the merge-time workflow comments with the merge commit and closes each claimed issue as completed, and refuses to act on unmerged pull requests.
- `check-release` gate for release pull requests, so every issue claimed by the pull requests in a release is either already closed or listed with a closing keyword before the release merges.
- Structured GitHub issue templates (bug report, feature request, task) with documented title and body standards, plus validation tests for them.

### Changed

- Consolidate guard result handling, the standalone CLI virtualenv bootstrap, and review helpers to remove duplicated code paths.
- Narrow the guard's bash parse fallback instead of treating every unparsed command as unsafe.
- Handle automated dependency pull requests in CI, and bump `filelock`.
- Documentation: reviewer kit for independent evaluation, strengthened discovery and conversion positioning, and manual dispatch for the post-release `dev` sync.

## 3.3.2

### Changed

- Upgrade `actions/setup-python` to `@v7` across all workflows, completing repo-wide action v7 modernization.
- Upgrade `softprops/action-gh-release` to `@v3` in release workflow.
- Update Dependabot configuration to bundle major version updates alongside minor/patch into weekly groups to eliminate unbundled PR noise.

## 3.3.1

### Changed

- Upgrade GitHub Actions workflows to v7 (`actions/checkout@v7`, `actions/setup-node@v7`, `actions/labeler@v7`, `actions/upload-artifact@v7`, and `astral-sh/setup-uv@v7`).
- Upgrade dependencies including `psutil` (7.2.2) and dev dependencies including `ruff` (0.16.7).
- Migrate `Phase` enumeration in `plugins/violin_guard/core/phases.py` to native Python 3.11 `StrEnum`.
- Configure Dependabot to target `dev` branch for all future dependency and action updates.

## 3.3.0

### Added

- Practitioner landing page covering how the guard works, an engagement walkthrough, an approach
  comparison, coverage, honest limits, and the questions testers ask; built with Vite and verified by a
  website workflow.
- Operator articles under `docs/articles/` on guardrails for agentic pentesting, coverage discipline for
  agent-assisted work, and how to evaluate an agentic pentest tool.
- GitHub Discussions as the community surface, GitHub Sponsors, and a repository social preview card.
- Benchmark aggregation that reports per-run distributions and pass@k across repeated runs.
- Structured HTTP observation parsing, so a saved batch probe supplies method, url, and status without
  prose inference.
- CI automation for pull request titles and descriptions, path-based area labels, weekly grouped
  Dependabot updates, and fast-forwarding `dev` after a release.

### Changed

- Saved evidence files must be declared through `violin_exec` and authenticated by the cited signed
  receipts before findings or benchmark scoring accept them; HTTP probes are rewritten safely before
  execution (curl gains `-i`, wget `-S`) so evidence always carries a literal status line.
- Benchmark runner children start with an isolated environment, so unrelated API keys and secrets are
  never inherited, and zero-finding runs are aggregated instead of rejected.
- Execute-code results are stored as a bounded, redacted representation; results that cannot be parsed
  are recorded as completed-with-error rather than dropped.
- Recency hints are suppressed during burst execution and active bounded batches, advisory hints no
  longer require `HERMES_YOLO_MODE`, and operational checks can bind an optional hypothesis during
  exploitation.
- CLI closeout generation discovers the project virtual environment dynamically, and missing CLI
  dependencies are reported with recovery commands.
- CI tests the supported Python 3.11 on Linux and Windows only.
- The container image installs Hermes into an isolated uv-managed Python 3.13 environment and copies a
  runtime whitelist instead of the whole checkout; `docs/` and `.github/` are no longer
  distribution-owned paths.

### Fixed

- Restore negative benchmark calibration and preserve per-command HTTP methods in compound probes.
- Keep host evaluator files out of every agent image layer; the golden fixture remains public
  for reproducibility and is not a secret holdout set.
- Require validated hypotheses to have findings with authenticated runtime evidence before reporting closes.
- Accept authenticated completed-with-error receipts for review without treating an execution error as proof.
- Include structured advisory hints, shared secret redaction, and guard improvements from PR #102.
- Hostname scope diagnostics state which setting to correct instead of restating the symptom.
- The landing page renders all 35 playbooks on load, its category and search filters work, and the guard
  simulator quotes the receipt fields and status vocabulary the guard actually seals.
- README registered-tool list includes `violin_submit_finding` and states the correct count of twelve.
- Corrected the README playbook, reference, and template counts to match the repository contents.
- Response header values in saved evidence (`Content-Length: 200`, `Retry-After: 429`) are no longer read
  as observed HTTP statuses.

### Removed

- The unused benchmark judge and indexer helpers, and the standalone `finding-FIND-NNN.md` template
  superseded by the findings store.

## 3.2.1

### Fixed

- Prevented phase validation failures from mutating PTT state.
- Made targeted hypothesis validation fail closed when scope is missing or malformed.
- Repaired Windows smoke coverage for bootstrap, scope, and target resolution.

### Changed

- Removed stale facades, dead helpers, unused telemetry, and the obsolete `search-exploit` CLI path.
- Removed the profile-level model and provider selection; Hermes now uses the operator's configuration.
- Simplified guard imports and internal call paths without changing the registered Hermes tool surface.
- Reworked the README and operator documentation around the current runtime, release gates, and benchmark limits.

## 3.2.0

### Maintenance

- Removed stale package facades, dead helper paths, and local skill-usage telemetry.
- Aligned operator documentation with the registered tools, package layout, PTT phase behavior, and benchmark verification limits.

### Core Architecture & Tool Consolidation
- **11 Core Tools**: Consolidated registered tool surface (17 -> 11 tools) by pruning 6 thin-proxy wrappers (`violin_httpx`, `violin_nuclei`, `violin_ffuf`, `violin_listener`, `violin_search_exploit`, `violin_check_command`) in favor of direct, unified `violin_exec`.
- **Subpackage Architecture**: Modularized `plugins/violin_guard` into direct subpackages (`core`, `gates`, `engine`, `handlers`) with explicit `__all__` exports and clean dependency isolation.

### Skills & Methodology Framework
- **7 Domain Skills**: Reorganized and routed pentest methodology across 7 distinct skill packages (`pentest`, `web-app`, `identity-auth`, `api-testing`, `business-logic`, `misconfig`, `llm-security`).
- **Coverage Matrix**: Automated bootstrap generation of coverage matrix from scope obligations with strict schema validation.
- **WSTG Methodology Gates**: Enforced methodology disposition checks before phase transitions and standardized canonical `FIND-NNN.md` schemas and templates.
- **Evidence & Discipline**: Documented two-step skill binding mechanics, evidence redaction patterns, and decisive raw response byte capture.

### Performance, Ergonomics & Concurrency Safety
- **AST Scope & Backend Caching**: LRU and TTL caching for AST scope parsing (`bashlex` + `yarl` + `netaddr`) and container probing.
- **Adaptive Poll Throttling**: Jittered backoff during long-running execution checks to eliminate CPU spin.
- **Robust Hypothesis Parsing**: Tolerates variable heading depths (`#`, `##`, `###`, bare) and parenthetical/confidence annotations without dropping validated records.
- **Process Safety**: Removed global environment mutations (`os.environ["ENG_DIR"]`), eliminated dynamic module inspection, and added advisory `filelock` protection on state/feedback logs.

### Code Quality & Maintenance
- Fix relative-path resolution in `abandon_execution` history tracking (`.resolve()`).
- Release sync-credit reservations via `try/finally` on mid-burst process kill.
- Validate listener port presence before integer coercion.
- Normalize command history with `splitlines()` (handles legacy CR line breaks).
- Use `hashlib.file_digest()` for single-pass SHA-256 in `receipt_integrity.py`.
- Automated GitHub release and tagging workflow (`.github/workflows/release.yml`) on push to `master`.

## 3.1.0

### Benchmark & Evaluation Framework
- **Automated Benchmark Runner (`benchmark/run.py`)**: End-to-end evaluation harness supporting automated multi-turn execution, OpenRouter provider integration, Docker containerization, and soft-timeout closeout handling.
- **Evidence-Gated Scorer & Proof Evaluator (`benchmark/score.py`, `proof.py`)**: Unified Technical-Proof Recall scoring with `require`/`require_any` sentinels, absence-proof verification for rate-limiting challenges, decisive payload matching, and reverse hypothesis-to-finding validation.
- **Automated AI Judge & Indexer (`benchmark/ai_judge.py`, `indexer.py`)**: Heuristic proof auditing, quality verification, and bounded artifact indexing for large engagements.
- **Calibration Suite**: 100% pass baseline on the 20-challenge Escape Duck Store reference suite (`--calibrate known-good` and `known-bad`).
- **Canonical Closeout Synthesis**: `generate-closeout` derives `findings.yaml` and executive `report.md` exclusively from verified `FIND-NNN.md` artifacts.

### Guard & Scope Policy
- **AST Scope Parser Rewrite**: `targets.py` scope checks rewritten using `bashlex` AST tokenization and `yarl` URL parsing, eliminating benign-command false positives while independently verifying pipelines, subshells, and compound commands.
- **Actionable Remediation Guidance**: Denials explicitly provide exact typed tool signatures and parameter templates (`violin_record_hypothesis`, `violin_record_ptt`, `violin_exec`) to eliminate turn-budget waste across models.
- **Record-As-You-Go Recency Gates**: Prevents deferred state writes, auto-logs friction events at block time, and resolves hypothesis disposition deadlocks.
- **Receipt Integrity & Parser Hardening**: Fail-closed state parsers, receipt integrity verifier, and single-approval bounded command batches (`violin_exec_burst`).

### Methodology & Playbooks
- **Consolidated 31 Playbooks, 17 References, 12 Templates**: Cleanly routed across the `pentest` orchestrator, `web-attacks` (5 playbooks), and `access-control` (3 playbooks) skills with single-source vulnerability routing.
- **Parallel Reconnaissance**: Mandated multi-agent parallel discovery patterns in `/goal` prompts and `SKILL.md §3` for high-throughput asset mapping.
- **Small Model Grounding & Worked Examples**: Added §7b worked tool-call parameter templates in `SKILL.md` to ensure seamless execution for open-weight models (Qwen 3.5/3.8, DeepSeek) without guard friction.
- **Single-Step Win Formalization**: Immediate hypothesis validation (`Validated`) coupled with atomic `FIND-NNN.md` evidence bundling upon decisive technical proof capture.

## 3.0.1

- Aligned workflow instructions in `.hermes.md`, `SKILL.md`, and `playbooks/recon.md` with Hermes v3 runtime tool contracts.
- Added cross-cutting evidence & verification discipline guidance (`references/evidence-and-verification-discipline.md`).
- Added authorized flag-capture (FLAGS) mode for lab/CTF engagements (`references/flags-mode.md`, `templates/flag-capture-register.md`).
- Enforced per-hypothesis discipline fields (`Confidence`, `Timebox`, `Cheapest test`, `Kill criteria`) and `Decoy Trail` logging.
- Fixed hypothesis board rewriter in `plugins/violin_guard/hypotheses.py` to preserve structural sections (`## Observations`, `## Decoy Trail`, `## Research Log`, `## Resolved Theories`).
- Updated `RecordHypothesisArgsModel` in `schemas.py` to expose discipline fields in tool parameters.
- Standardized workspace `AGENTS.md` to follow industry AI developer guidance best practices.

## 3.0.0

- Made the Windows workflow smoke harness use the repository virtual-environment runtime when available, avoiding false failures from a dependency-free system Python.
- Made background execution restart-safe by recording PID creation times and deadlines, refusing to signal reused PIDs, recovering matching processes, and marking missing processes as lost; new pending batches now use collision-resistant UUIDs.
- Made burst execution atomic at admission: every command is preflighted before launch, required sync credit is reserved under one lock, and unused reservations are returned after partial batches.
- Fixed target extraction for dotted identifiers and direct `/dev/tcp`/`/dev/udp` redirections, and prevented network-capable local-looking commands from bypassing execution accounting.
- Made interrupted skill preparation recoverable with expiring reservations and stale-owner protection; batch review now remains tied to the delivered execution receipt.
- Stabilized the core engagement workflow: domain/URL-only scopes now validate, runtime execution cannot substitute another scope file, PTT/review CLI contracts carry skill metadata, and review reuses the active delivered binding.
- Added receipt-backed skill routing, delivery, task binding, browser enforcement, Kali auto-backend selection, proof-based finding review, and semantic anti-stuck enforcement.
- Replaced marker-file authorization with two-turn skill preparation and receipt diagnostics; legacy markers can only infer a unique session ID during migration.
- Allowed direct host-local `init-engagement --host` bootstrapping, persisted runtime session identity before skill delivery, and blocked shell-indirection workarounds.
- Scoped skill cooldowns to Hermes model API requests so the next tool-loop continuation unlocks automatically, while batch review no longer replaces the active execution-skill binding.
- Migrated guard tool schemas and parameter validation to Pydantic v2.
- Replaced platform-specific process termination with cross-platform `psutil` process tree traversal and cleanup.
- Upgraded target IP/CIDR scope policy arithmetic to `netaddr.IPSet` and RFC 3986 URL parsing to `yarl`.
- Replaced shell regexes in terminal policy with `bashlex` AST tokenization and command parsing.

## 2.0.8

- Expanded Duck Store benchmark challenges from 14 to 20 article-parity vulnerabilities, matching Redpick's verified findings across 7 categories with correct severity distribution.
- Renamed benchmark engagement prompt from `anti-walkthrough.md` to `engage.md` and added a post-engagement `report.md` prompt that runs the scorer and generates a comprehensive benchmark report.

## 2.0.7

- Added a Duck Store benchmark harness: 4-file suite (`score.py`, `challenges.json`, `scope.yaml`, `engage.md`) to evaluate Violin against escape.tech's Duck Store with repeatable, evidence-gated scoring.
- Rewrote `score.py` with 8 evidence-gated fixes from the first benchmark run: corrected PTT path (`state/ptt.md`), hypothesis status per-block parsing, word-boundary pattern matching, HTTP proof-signature quality gate, auditable per-challenge output, honest compliance reporting (empty history reports UNKNOWN), calibration dry-run mode, and coverage-vs-quality split in output.
- Added explicit model section to `config.yaml`; profiles do not inherit the default model configuration.

## 2.0.6

- Resolved the current CodeQL standard quality findings by making intentional exception fallbacks explicit and removing unused test and hypothesis variables.

## 2.0.5

- Restored exact-repeat detection for execution history entries with receipt paths and added unambiguous command-length metadata while retaining compatibility with existing history files.

## 2.0.4

- Hard-blocked callback and research endpoints when supplied as primary assessment targets while preserving their approved secondary-only use, including burst execution.

## 2.0.3

- Fixed raw-terminal compound-command classification so every pipeline, logical, semicolon, and newline segment is checked independently, and package/source exemptions require every URL in the segment to use an approved source host.

## 2.0.2

- Restricted all GitHub Actions workflow tokens to read-only repository contents, resolving the three least-privilege code-scanning alerts without changing workflow behavior.

## 2.0.1

- Upgraded the pytest development dependency to 9.0.3 or later to address CVE-2025-71176 insecure temporary-directory handling.

## 2.0.0

- Added model-visible `violin_status` diagnostics, phase-aware 10/20-command sync windows, a 350-iteration profile budget, and atomic `violin_review_batch` reconciliation with optional receipt-backed finding output.
- Fixed explicit PTT task creation so the requested phase controls the row's actual table placement, and unified CLI/plugin PTT review state.
- Removed message-count heartbeat locks; executed-command heartbeat checks remain phase-aware and are suppressed during exploit-heavy phases.
- Made the existing `violin_exec` contract explicit for every installed non-interactive Kali/Parrot CLI tool, and removed the partial target-tool name list from raw-terminal classification in favor of generic target-literal detection.
- Reorganised the guard into focused top-level modules under `plugins/violin_guard/`, with separate history, result, execution, state, target, and service responsibilities.
- Split web-injection and access-control playbooks into the on-demand `web-attacks` and `access-control` skills while keeping `pentest` as the engagement orchestrator.
- Required an explicit primary target at the command boundary and added operator-approved callback hosts that cannot be promoted to assessment targets.
- Added guarded listener execution and audited pending-batch rebinding without weakening the required PTT review and synchronization checkpoint.
- Added engagement-bound audit receipts for Hermes `execute_code` calls, while documenting terminal detection as best-effort rather than scope enforcement.
- Replaced regex-based target parsing with Python standard-library shell, URL, IP/CIDR, and MIME parsers; this keeps scope enforcement dependency-free while reducing parser ambiguity.
- Kept target parsing and target-scope enforcement in `plugins/violin_guard/targets.py`, leaving `command.py` focused on policy orchestration.
- Allowed `violin_record_ptt` to start one untouched phase-bound task, removing the initial active-task deadlock while retaining fail-closed batch reviews.
- Made hypothesis parsing field-order independent and fixed template rewrites so recorded hypotheses are never written inside the template comment.
- Clarified typed nmap all-port input: use `ports: "1-65535"`, not the `-p-` flag form.
- Bootstrap engagement-local `exploits/` and phase evidence directories, and direct local scripts and output away from `/tmp` while preserving explicitly labelled remote-target `/tmp` payloads.
- Fixed target extraction so local dotted output/script names are not treated as hosts, and Bash `/dev/tcp` or `/dev/udp` endpoints retain their full host and port boundary.
- Canonicalized hypothesis IDs supplied as `H-001`, removed malformed duplicate headings on rewrite, and compare scoped hypothesis targets correctly when they include a URL or port.
- Kept review binding fail-closed while removing the need to manually copy an opaque pending batch ID into every PTT note.

## 1.3.1

- Enforced scope authorization, exclusions, phase-aligned PTT tasks, and relevant hypotheses at the execution boundary.
- Made synchronization credits apply to all target-touching commands and bound reviewed batches to their captured PTT task.
- Serialized guard state transitions, fixed isolated plugin imports, and made release and PowerShell smoke checks fail reliably.

## 1.3.0

- Consolidated Violin Guard into a Hermes-native plugin.
- Made command history executor-owned and PTT review explicit.
