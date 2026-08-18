#!/usr/bin/env python3
"""run.py — Automated Hermes Profile Benchmark Runner with OpenRouter integration.

Executes Hermes non-interactively using the target profile against a benchmark lab target,
manages engagement state, and scores evidence automatically via score.py.
"""

import argparse
import copy
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path

import yaml
from yarl import URL

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from benchmark.score import generate_markdown_summary, print_result, score_engagement  # noqa: E402
from plugins.violin_guard.core.receipt_integrity import RECEIPT_KEY_ENV  # noqa: E402
from plugins.violin_guard.gates.command import validate_scope  # noqa: E402

_DEFAULT_HERMES_MAX_TOKENS = 32_000
_CLOSEOUT_TIMEOUT_SECONDS = 600


def _engagement_needs_closeout(eng_dir: Path) -> bool:
    """Return whether Hermes stopped before producing a complete closeout.

    Closeout is gated on the artifacts the scorer actually consumes: at least
    one canonical FIND file plus both reporting deliverables. Unchecked PTT
    task rows are NOT a trigger — a leftover task marker used to fire a
    continuation pass that re-ran the entire assessment instead of closing out.
    """
    findings_dir = eng_dir / "evidence" / "findings"
    if not findings_dir.exists() or not any(findings_dir.glob("FIND-*.md")):
        return True
    return not all(
        (eng_dir / relative).is_file()
        for relative in ("reporting/report.md", "retrospective/retrospective.md")
    )


def _closeout_command(args: argparse.Namespace, eng_dir: Path) -> list[str]:
    """Build a continuation goal that ONLY closes an existing engagement.

    The wording must be surgical: the assessment and its evidence are final,
    and the agent is forbidden from running new tests, touching evidence, or
    re-verifying findings. The previous wording ("Continue the existing
    authorized engagement") was read as license to re-run the whole
    assessment (255 messages / 20m50s instead of a minutes-long closeout).
    """
    command = [
        "hermes",
        "chat",
        "-p",
        "violin",
        "--provider",
        args.provider,
        "--yolo",
        "-q",
        f"/goal The engagement in {eng_dir.resolve()} is COMPLETE and its evidence is final. "
        "Do NOT run any new tests, scans, commands, or verification against the target, and do NOT modify "
        "evidence, findings, hypotheses, or any state files. ONLY finalize closeout: if "
        "reporting/report.md is missing, generate it from the existing evidence/findings/FIND-*.md files "
        "(prefer `python scripts/violin_guard.py generate-closeout`); if "
        "retrospective/retrospective.md is missing, write it; then update state/ptt.md task "
        "statuses to reflect completed work. "
        "Bookkeeping only: if any Validated hypothesis on the hypothesis board lacks a "
        "'Linked findings' field naming the FIND-*.md file(s) that document its result, "
        "update it via violin_record_hypothesis so each validated claim points at its "
        "canonical finding — do not create new hypotheses or findings, and do not "
        "re-verify evidence. "
        "Never inspect benchmark answer keys, scorer code, challenge inventories, walkthroughs, "
        "or target-specific solution material.",
    ]
    if args.model:
        command.extend(["-m", args.model])
    return command


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated Hermes Profile Benchmark Runner with OpenRouter support."
    )
    parser.add_argument(
        "--eng-dir",
        type=Path,
        default=None,
        help="Engagement directory for benchmark execution (default: unique benchmark run directory)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="deepseek/deepseek-v4-flash-0731",
        help="Optional LLM model ID or openrouter/model-name (default: deepseek/deepseek-v4-flash-latest)",
    )
    parser.add_argument(
        "--skill",
        type=str,
        default="",
        help="Optional skill to preload (e.g. pentest)",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="openrouter",
        help="Hermes LLM provider (e.g. openrouter, openai, custom) (default: openrouter)",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default="https://openrouter.ai/api/v1",
        help="OpenAI-compatible API base URL (default: https://openrouter.ai/api/v1)",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="https://duck-store.escape.tech",
        help="Target host or URL for the benchmark run (default: https://duck-store.escape.tech)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Initialize engagement directory and print commands without executing Hermes CLI",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional path to write benchmark results JSON",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        help="Optional path to write markdown summary",
    )
    return parser.parse_args()


def _scope_for_target(target: str) -> dict:
    """Render the canonical benchmark fixture for one URL, domain, or IP target."""
    fixture_path = REPO_ROOT / "benchmark" / "targets" / "duck-store" / "scope.yaml"
    scope = copy.deepcopy(yaml.safe_load(fixture_path.read_text(encoding="utf-8")))
    raw_target = target.strip()
    parsed = URL(raw_target if "://" in raw_target else f"https://{raw_target}")
    if parsed.scheme not in {"http", "https"} or not parsed.host:
        raise ValueError("benchmark target must be an HTTP(S) URL, domain, or IP address")
    host = parsed.host
    try:
        ipaddress.ip_address(host)
        addresses = [host]
        domains: list[str] = []
    except ValueError:
        addresses = []
        domains = [host]
    base_url = str(parsed.with_path("").with_query(None).with_fragment(None)).rstrip("/")
    scope["engagement"]["date"] = date.today().isoformat()
    scope["targets"] = {
        "ip_addresses": addresses,
        "domains": domains,
        "urls": [str(parsed)],
        "in_scope_urls": [str(parsed)],
    }
    excluded_paths = list((scope.get("exclusions") or {}).get("paths") or [])
    scope.setdefault("exclusions", {})["urls"] = [
        f"{base_url}/{path.lstrip('/')}" for path in excluded_paths
    ]
    benchmark = scope.get("benchmark")
    if isinstance(benchmark, dict):
        benchmark.pop("openapi_spec", None)
    # Engagement brief (client-provided facts, framework-owned): seed the
    # target's engage.md so operational facts (default credentials, register
    # first, reset window) reach the agent via scope.yaml — the file the agent
    # is already required to validate — instead of the prompt. The /goal prompt
    # stays task-only.
    brief_path = fixture_path.with_name("engage.md")
    if brief_path.is_file():
        brief = brief_path.read_text(encoding="utf-8").strip()
        if brief:
            scope.setdefault("engagement", {})["brief"] = brief
    # Engagement audit mode: a generic "structured engagement" flag the
    # framework gates on. Benchmark harness sets it; a real client engagement
    # with strict record-keeping can set the same flag. No benchmark concept
    # leaks into framework logic.
    scope.setdefault("engagement", {})["audit_mode"] = True
    # Strict engagement record-keeping: every WSTG methodology category must be
    # dispositioned with evidence before VULN_RESEARCH closes. Same generic
    # client-style flag as audit_mode; a real strict client can set it too.
    scope.setdefault("engagement", {})["require_methodology_gates"] = True
    # Coverage obligations: route-level API scope a client would provide at
    # kickoff (in-scope endpoints), NOT vulnerability names — the agent must
    # still discover what is vulnerable. Derived from the target's endpoint
    # inventory; the framework's coverage gate then requires an evidence-backed
    # matrix cell per obligation.
    obligations_path = fixture_path.parent / "challenges.json"
    if obligations_path.is_file():
        try:
            challenges = json.loads(obligations_path.read_text(encoding="utf-8")).get(
                "challenges", []
            )
        except (OSError, ValueError):
            challenges = []
        obligations: list[str] = []
        for ch in challenges:
            endpoint = ch.get("endpoint") or ""
            candidates = endpoint if isinstance(endpoint, list) else [endpoint]
            for item in candidates:
                item = str(item or "").strip()
                if item and item not in obligations:
                    obligations.append(item)
        scope.setdefault("engagement", {})["coverage_obligations"] = obligations
    return scope


def init_benchmark_engagement(eng_dir: Path, target: str) -> None:
    """Initialize benchmark engagement directory structure cleanly (idempotent reset)."""
    resolved_eng = eng_dir.resolve()
    resolved_engagements = (REPO_ROOT / "engagements").resolve()
    temporary_root = Path(tempfile.gettempdir()).resolve()
    pytest_root = (REPO_ROOT / ".pytest-tmp").resolve()
    if not (
        resolved_eng == resolved_engagements
        or resolved_engagements in resolved_eng.parents
        or temporary_root in resolved_eng.parents
        or pytest_root in resolved_eng.parents
    ):
        raise ValueError(
            f"Safety error: engagement directory {resolved_eng} must be inside {resolved_engagements}"
        )

    if eng_dir.exists():
        for item in eng_dir.iterdir():
            try:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
            except Exception:
                pass

    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope").mkdir(parents=True, exist_ok=True)
    (eng_dir / "state").mkdir(parents=True, exist_ok=True)
    (eng_dir / "evidence").mkdir(parents=True, exist_ok=True)
    for phase_dir in (
        "recon",
        "recon/active",
        "recon/passive",
        "vuln-research",
        "exploitation",
        "post-exploitation",
        "privesc",
        "flags",
        "reporting",
        "retrospective",
        "executions",
    ):
        (eng_dir / "evidence" / phase_dir).mkdir(parents=True, exist_ok=True)
    (eng_dir / "exploits").mkdir(parents=True, exist_ok=True)

    scope_yaml = eng_dir / "scope" / "scope.yaml"
    scope_yaml.write_text(
        yaml.safe_dump(_scope_for_target(target), sort_keys=False), encoding="utf-8"
    )
    validation = validate_scope(scope_yaml)
    if validation.errors:
        raise ValueError("generated benchmark scope is invalid: " + "; ".join(validation.errors))

    ptt_md = eng_dir / "state" / "ptt.md"
    ptt_md.write_text(
        """# Pentesting Task Tree (PTT)

## Phase: RECON

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-101 | [~] | Reconnaissance & Tech Detection | benchmark bootstrap; record exact request/response evidence |

## Phase: VULN_RESEARCH

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-102 | [ ] | Vulnerability Assessment | test and disposition every mapped route, method, parameter, and role boundary |

## Phase: EXPLOITATION

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-103 | [ ] | Exploitation & Proof Verification | validate only in-scope, non-destructive findings |
""",
        encoding="utf-8",
    )

    hyp_md = eng_dir / "hypotheses.md"
    hyp_md.write_text(
        """# Hypothesis Board
### H-001: Initial Target Assessment
**Status:** Candidate
**Linked challenges:**
""",
        encoding="utf-8",
    )

    feedback_md = eng_dir / "state" / "framework_feedback.md"
    feedback_md.write_text(
        """# Violin Framework Feedback & Friction Log
If you encounter tool friction, missing binaries/CLI tools, guard pathing errors, or framework bugs in Violin during this assessment, record them below.

CRITICAL: Whenever you inspect or read the guard codebase (e.g. plugins/violin_guard/ or guard scripts) to understand how a tool works, why a command was blocked, or how state is managed, log the occurrence below with:
1. Category: Guard Code Inspection
2. Issue Description: Which guard file/code you read and what you were trying to understand
3. Impact / Workaround: What confusion or error forced you to read the code
4. Prevention Suggestion: What specifically would prevent needing to read guard code in the future (e.g. clearer error messages, self-documenting CLI parameters, tool docs, or explicit return details)

| Timestamp | Category | Issue Description | Impact / Workaround | Prevention Suggestion |
|---|---|---|---|---|
""",
        encoding="utf-8",
    )

    # Seed the matrix from the exact client-style obligations in scope.yaml.
    # The close gate requires a flat coverage map keyed by those strings; generic
    # nested WSTG category placeholders make every initialized engagement fail
    # schema validation before the agent can begin testing.
    scope = yaml.safe_load(scope_yaml.read_text(encoding="utf-8")) or {}
    obligations = [
        str(item).strip()
        for item in ((scope.get("engagement") or {}).get("coverage_obligations") or [])
        if str(item).strip()
    ]
    coverage = {
        "coverage": {
            obligation.lower(): {"status": "pending", "evidence_or_reason": ""}
            for obligation in obligations
        }
    }
    (eng_dir / "state" / "coverage-matrix.yaml").write_text(
        yaml.safe_dump(coverage, sort_keys=False), encoding="utf-8"
    )

    hist_md = eng_dir / "state" / "history.md"
    hist_md.write_text(
        "# Command History Log\n# Format: TIMESTAMP | PHASE | TARGET | CMD\n",
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.eng_dir is not None:
        eng_dir = args.eng_dir
    else:
        eng_dir = REPO_ROOT / "engagements" / f"benchmark-run-{timestamp}"

    print("=== HERMES PROFILE BENCHMARK RUNNER ===")
    print(f"Engagement Dir : {eng_dir}")
    print(f"Model          : {args.model}")
    print(f"Provider       : {args.provider}")
    print(f"API Base       : {args.api_base}")
    print(f"Target         : {args.target}")

    init_benchmark_engagement(eng_dir, args.target)

    receipt_key = secrets.token_bytes(32)
    env = os.environ.copy()
    env["ENG_DIR"] = str(eng_dir.resolve())
    env[RECEIPT_KEY_ENV] = receipt_key.hex()
    env["OPENAI_API_BASE"] = args.api_base
    env["OPENAI_BASE_URL"] = args.api_base
    env["CUSTOM_BASE_URL"] = args.api_base
    # OpenRouter rejects requests whose declared output ceiling exceeds the
    # account's affordable budget, even when the model would stop earlier.
    # Keep the benchmark provider-safe while allowing an explicit override for
    # accounts with a larger entitlement.
    configured_max_tokens = os.environ.get("VIOLIN_BENCHMARK_MAX_TOKENS", "").strip()
    env["HERMES_MAX_TOKENS"] = configured_max_tokens or str(_DEFAULT_HERMES_MAX_TOKENS)
    if "NOUS_API_KEY" in env and "OPENAI_API_KEY" not in env:
        env["OPENAI_API_KEY"] = env["NOUS_API_KEY"]
    if "OPENROUTER_API_KEY" in env and "OPENAI_API_KEY" not in env:
        env["OPENAI_API_KEY"] = env["OPENROUTER_API_KEY"]
    if "OPENAI_API_KEY" not in env:
        env["OPENAI_API_KEY"] = "not-needed"

    venv_scripts = str(REPO_ROOT / ".venv" / "Scripts")
    venv_bin = str(REPO_ROOT / ".venv" / "bin")
    current_path = env.get("PATH", "")
    env["PATH"] = os.pathsep.join([path for path in (venv_scripts, venv_bin, current_path) if path])
    env["PYTHONPATH"] = str(REPO_ROOT)

    cmd = [
        "hermes",
        "chat",
        "-p",
        "violin",
        "--provider",
        args.provider,
        "--yolo",
        "-q",
        f"/goal Perform an exhaustive authorized security assessment of {args.target} using the engagement in {eng_dir.resolve()}. "
        "Log tool friction, guard errors, and any guard-code inspection in state/framework_feedback.md. "
        "Never inspect benchmark answer keys, scorer code, challenge inventories, walkthroughs, or target-specific solution material.",
    ]
    if args.skill:
        cmd.extend(["-s", args.skill])
    if args.model:
        cmd.extend(["-m", args.model])

    print(f"\nExecution Command: {' '.join(cmd)}")

    started = datetime.now()
    runner = {
        "status": "dry_run" if args.dry_run else "not_started",
        "valid": False,
        "exit_code": None,
        "provider": args.provider,
        "model": args.model,
        "started_at": started.isoformat(),
        "completed_at": None,
        "duration_seconds": None,
        "failure_reason": None,
    }
    if args.dry_run:
        print("[DRY-RUN] Benchmark engagement structure prepared. Skipping Hermes execution.")
    else:
        hermes_bin = shutil.which("hermes")
        if not hermes_bin:
            runner.update(
                status="failed_to_start",
                valid=False,
                failure_reason="hermes binary not found on PATH",
            )
            print("[ERROR] 'hermes' binary not found on PATH.")
        else:
            try:
                completed = subprocess.run(cmd, env=env, cwd=eng_dir, check=False)
                runner["exit_code"] = completed.returncode
                runner["valid"] = completed.returncode == 0
                runner["status"] = "completed" if completed.returncode == 0 else "failed"
                if completed.returncode != 0:
                    runner["failure_reason"] = f"Hermes exited with status {completed.returncode}"
            except Exception as exc:  # noqa: BLE001
                runner.update(status="failed_to_start", valid=False, failure_reason=str(exc))
                print(f"[ERROR] Hermes execution failed to start: {exc}")

            # Hermes can return successfully after the substantive assessment
            # while leaving PTT closeout/reporting work unfinished. Run a
            # bounded continuation pass so scoring never treats that partial
            # state as a completed engagement. Closeout is best-effort: a
            # timeout or nonzero exit must NOT invalidate a run whose
            # substantive evidence already exists (scoring proceeds), it is
            # reported as a soft warning instead.
            runner["closeout_attempts"] = []
            runner["closeout_complete"] = False
            if runner["valid"]:
                for _attempt in range(2):
                    if not _engagement_needs_closeout(eng_dir):
                        break
                    try:
                        closeout = subprocess.run(
                            _closeout_command(args, eng_dir),
                            env=env,
                            cwd=eng_dir,
                            check=False,
                            timeout=_CLOSEOUT_TIMEOUT_SECONDS,
                        )
                    except subprocess.TimeoutExpired:
                        runner["closeout_attempts"].append("timeout")
                        runner["closeout_warning"] = (
                            f"Hermes closeout exceeded {_CLOSEOUT_TIMEOUT_SECONDS} seconds; "
                            "scoring proceeds on substantive evidence"
                        )
                        break
                    runner["closeout_attempts"].append(closeout.returncode)
                    if closeout.returncode != 0:
                        runner["closeout_warning"] = (
                            f"Hermes closeout exited with status {closeout.returncode}"
                        )
                        break
                runner["closeout_complete"] = not _engagement_needs_closeout(eng_dir)

            history_path = eng_dir / "state" / "history.md"
            execution_dir = eng_dir / "evidence" / "executions"
            has_commands = history_path.exists() and any(
                line.strip().startswith("-")
                for line in history_path.read_text(encoding="utf-8", errors="replace").splitlines()
            )
            has_receipts = execution_dir.exists() and any(execution_dir.glob("*.json"))
            if runner["valid"] and not (has_commands and has_receipts):
                runner.update(
                    status="failed",
                    valid=False,
                    failure_reason="Hermes returned without producing benchmark execution evidence",
                )

    finished = datetime.now()
    runner["completed_at"] = finished.isoformat()
    runner["duration_seconds"] = round((finished - started).total_seconds(), 3)

    # Score engagement results
    print("\n=== SCORING ENGAGEMENT RESULTS ===")
    results = score_engagement(eng_dir, receipt_key=receipt_key)
    results["runner"] = runner
    results["score_benchmark_pass"] = results["benchmark_pass"]
    results["valid"] = runner["valid"]
    results["benchmark_pass"] = bool(runner["valid"] and results["benchmark_pass"])
    print_result(results)

    # Always write unique results into eng_dir
    (eng_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (eng_dir / "results.md").write_text(generate_markdown_summary(results), encoding="utf-8")
    print(f"Wrote benchmark results to {eng_dir / 'results.json'} and {eng_dir / 'results.md'}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote JSON results to {args.json_out}")

    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        md_summary = generate_markdown_summary(results)
        args.markdown_out.write_text(md_summary, encoding="utf-8")
        print(f"Wrote Markdown summary to {args.markdown_out}")
    if args.dry_run:
        return 0
    return 0 if runner["valid"] and results["benchmark_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
