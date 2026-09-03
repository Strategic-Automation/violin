#!/usr/bin/env python3
"""Automated Hermes profile benchmark runner for OpenAI-compatible providers.

Executes Hermes non-interactively using the target profile against a benchmark lab target,
manages engagement state, and evaluates it only when the private evaluator is present.
"""

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from yarl import URL

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from plugins.violin_guard.core.receipt_integrity import RECEIPT_SIGNING_KEY_ENV  # noqa: E402
from plugins.violin_guard.gates.command import validate_scope  # noqa: E402

_DEFAULT_HERMES_MAX_TOKENS = 32_000
_HERMES_ENV_ALLOWLIST = frozenset(
    {
        "APPDATA",
        "COLORTERM",
        "COMSPEC",
        "HERMES_YOLO_MODE",
        "HOME",
        "HOSTNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "SSH_AUTH_SOCK",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)
_PROVIDER_KEY_ENV = {
    "nous": "NOUS_API_KEY",
    "openai": "OPENAI_API_KEY",
    "opencode-go": "OPENCODE_GO_API_KEY",
    "opencode_go": "OPENCODE_GO_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}
_COVERAGE_OBLIGATIONS = (
    "POST /api/v1/auth/login",
    "POST /api/v1/auth/login/totp",
    "POST /api/v1/auth/register",
    "GET /api/v1/users/",
    "GET /api/v1/users/{uuid}",
    "PUT /api/v1/users/me/profile",
    "GET /api/v1/products/filter/by-color",
    "POST /api/v1/testimonials/",
    "PUT /api/v1/testimonials/{id}",
    "POST /api/v1/uploads/import-from-url",
    "GET /api/v1/uploads/fetch-url",
    "GET /api/v1/orders/{id}",
    "GET /api/v1/admin/users",
    "POST /api/v1/cart/add",
    "PUT /api/v1/cart/items/{id}",
    "POST /api/v1/orders/checkout",
    "GET /api/v1/orders/coupons",
    "/...?redirect=",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automated Hermes profile benchmark runner.")
    parser.add_argument(
        "--eng-dir",
        type=Path,
        default=None,
        help="Engagement directory for benchmark execution (default: unique benchmark run directory)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="",
        help="Optional Hermes model ID; omitted uses the operator's Hermes configuration",
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
        default="",
        help="Optional provider label used for manifest metadata and API-key selection",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default="",
        help="Optional OpenAI-compatible base URL; omitted uses Hermes configuration",
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
        "--target-isolation-id",
        default="",
        help="Immutable snapshot/reset identifier supplied by the target orchestrator",
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
    return parser.parse_args(argv)


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _git_output(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, check=False, capture_output=True, text=True
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _hermes_environment(
    args: argparse.Namespace,
    eng_dir: Path,
    signing_key_bytes: bytes,
) -> dict[str, str]:
    """Build a narrow child environment without forwarding unrelated secrets."""
    env = {key: value for key, value in os.environ.items() if key.upper() in _HERMES_ENV_ALLOWLIST}
    env["ENG_DIR"] = str(eng_dir.resolve())
    env[RECEIPT_SIGNING_KEY_ENV] = signing_key_bytes.hex()
    env["HERMES_YOLO_MODE"] = "1"

    api_base = str(args.api_base or "").strip()
    if api_base:
        env["OPENAI_API_BASE"] = api_base
        env["OPENAI_BASE_URL"] = api_base
        env["CUSTOM_BASE_URL"] = api_base

    provider = str(args.provider or "").strip().casefold()
    key_name = _PROVIDER_KEY_ENV.get(provider)
    if key_name is None and api_base:
        key_name = "OPENAI_API_KEY"
    if key_name and (key_value := os.environ.get(key_name)):
        env[key_name] = key_value
        env["OPENAI_API_KEY"] = key_value

    configured_max_tokens = os.environ.get("VIOLIN_BENCHMARK_MAX_TOKENS", "").strip()
    env["HERMES_MAX_TOKENS"] = configured_max_tokens or str(_DEFAULT_HERMES_MAX_TOKENS)

    venv_scripts = str(REPO_ROOT / ".venv" / "Scripts")
    venv_bin = str(REPO_ROOT / ".venv" / "bin")
    current_path = env.get("PATH", "")
    env["PATH"] = os.pathsep.join([path for path in (venv_scripts, venv_bin, current_path) if path])
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def _run_manifest(
    args: argparse.Namespace,
    eng_dir: Path,
    *,
    public_key: bytes,
    started_at: str,
) -> dict:
    source_paths = [
        Path(__file__),
        REPO_ROOT / "benchmark" / "targets" / "duck-store" / "scope.yaml",
        REPO_ROOT / "benchmark" / "targets" / "duck-store" / "engage.md",
        REPO_ROOT / "plugins" / "violin_guard" / "core" / "findings.py",
        REPO_ROOT / "plugins" / "violin_guard" / "core" / "receipt_integrity.py",
    ]
    isolation_id = str(getattr(args, "target_isolation_id", "") or "").strip()
    return {
        "schema_version": 1,
        "run_id": eng_dir.name,
        "started_at": started_at,
        "target": args.target,
        "target_isolation": {
            "declared": bool(isolation_id),
            "snapshot_or_reset_id": isolation_id or None,
            "reason": None
            if isolation_id
            else "no immutable target snapshot/reset identity was supplied",
        },
        "model": args.model,
        "provider": args.provider,
        "receipt_verification": {
            "algorithm": "Ed25519",
            "public_key_hex": public_key.hex(),
        },
        "source": {
            "git_commit": _git_output("rev-parse", "HEAD"),
            "git_dirty": bool(_git_output("status", "--porcelain")),
            "sha256": {
                path.relative_to(REPO_ROOT).as_posix(): _sha256(path) for path in source_paths
            },
        },
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "container_id": os.environ.get("HOSTNAME"),
            "image_digest": os.environ.get("VIOLIN_BENCHMARK_IMAGE_DIGEST"),
        },
        "status": "running",
    }


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
        benchmark["openapi_spec"] = f"{base_url}/openapi.json"
    # Engagement brief (client-provided facts, framework-owned): seed the
    # target's engage.md so operational facts (default credentials, register
    # first, reset window) reach the agent via scope.yaml — the file the agent
    # is already required to validate — instead of the prompt. The /goal prompt
    # stays task-only.
    brief_path = fixture_path.with_name("engage.md")
    if brief_path.is_file():
        brief = (
            brief_path.read_text(encoding="utf-8")
            .replace("https://duck-store.escape.tech", base_url)
            .strip()
        )
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
    scope.setdefault("engagement", {})["coverage_obligations"] = list(_COVERAGE_OBLIGATIONS)
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

    signing_key = Ed25519PrivateKey.generate()
    signing_key_bytes = signing_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_key_bytes = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    started = datetime.now(UTC)
    manifest = _run_manifest(
        args,
        eng_dir,
        public_key=public_key_bytes,
        started_at=started.isoformat(),
    )
    manifest_path = eng_dir / "run-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    env = _hermes_environment(args, eng_dir, signing_key_bytes)

    cmd = [
        "hermes",
        "chat",
        "-p",
        "violin",
        "--yolo",
        "-q",
        f"/goal Perform an exhaustive authorized security assessment of {args.target} using the engagement in {eng_dir.resolve()}. "
        "Test every in-scope obligation and submit one finding per confirmed vulnerability — never bundle distinct flaws into one finding. "
        "Follow the pentest skill and its references end-to-end. "
        "Record any tool friction, guard errors, or framework bugs you encounter in state/framework_feedback.md.",
    ]
    if args.skill:
        cmd.extend(["-s", args.skill])
    if args.model:
        cmd.extend(["-m", args.model])
    # A custom base URL is supplied through the child environment. Model
    # selection remains an explicit operator input or Hermes configuration.

    print(f"\nExecution Command: {' '.join(cmd)}")

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

    finished = datetime.now(UTC)
    runner["completed_at"] = finished.isoformat()
    runner["duration_seconds"] = round((finished - started).total_seconds(), 3)

    results: dict = {"schema_version": 2, "runner": runner, "valid": runner["valid"]}
    golden_path = REPO_ROOT / "benchmark" / "private" / "duck-store-golden.json"
    if golden_path.is_file():
        from benchmark.score import (  # noqa: PLC0415
            generate_markdown_summary,
            print_result,
            score_engagement,
        )

        print("\n=== PRIVATE GOLDEN EVALUATION ===")
        results.update(score_engagement(eng_dir, receipt_public_key=public_key_bytes))
        results["runner"] = runner
        results["valid"] = runner["valid"]
        results["benchmark_pass"] = bool(runner["valid"] and results["benchmark_pass"])
        print_result(results)
        markdown = generate_markdown_summary(results)
    else:
        results["evaluation"] = "pending_private_evaluator"
        markdown = "# Violin Benchmark Run\n\nPrivate evaluation pending.\n"

    (eng_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (eng_dir / "results.md").write_text(markdown, encoding="utf-8")
    manifest.update(
        status=runner["status"],
        completed_at=finished.isoformat(),
        results_sha256=_sha256(eng_dir / "results.json"),
    )
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote benchmark results to {eng_dir / 'results.json'} and {eng_dir / 'results.md'}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote JSON results to {args.json_out}")

    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(markdown, encoding="utf-8")
        print(f"Wrote Markdown summary to {args.markdown_out}")
    if args.dry_run:
        return 0
    if not runner["valid"]:
        return 1
    return 0 if "benchmark_pass" not in results or results["benchmark_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
