# Changelog

## 2.0.9

- Collapsed newlines in history.md so multi-line commands match the pending-batch comparison with sync.json.
- Skipped tokens after credential flags (`-u`, `--user`, `-p`, `-H`, `-dc-ip`) in target extraction so dotted usernames are not mistaken for assessment targets.
- Added tool environment notes to exploitation playbook covering impacket version, bloodyAD GenericWrite limits, and xfreerdp/evil-winrm TTY requirements.

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

- Enforced scope authorisation, exclusions, phase-aligned PTT tasks, and relevant hypotheses at the execution boundary.
- Made synchronization credits apply to all target-touching commands and bound reviewed batches to their captured PTT task.
- Serialized guard state transitions, fixed isolated plugin imports, and made release and PowerShell smoke checks fail reliably.

## 1.3.0

- Consolidated Violin Guard into a Hermes-native plugin.
- Made command history executor-owned and PTT review explicit.
