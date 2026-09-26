#!/usr/bin/env python3
"""Automated Hermes profile benchmark runner for OpenAI-compatible providers.

Executes Hermes non-interactively using the target profile against a benchmark lab target,
manages engagement state, and evaluates it only when the private evaluator is present.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from benchmark.engagement import (  # noqa: E402
    _scope_for_target as _scope_for_target,
)
from benchmark.engagement import init_benchmark_engagement  # noqa: E402
from plugins.violin_guard.core.evidence.receipt_integrity import (  # noqa: E402
    RECEIPT_SIGNING_KEY_ENV,
)

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
        REPO_ROOT / "benchmark" / "engagement.py",
        REPO_ROOT / "benchmark" / "targets" / "duck-store" / "scope.yaml",
        REPO_ROOT / "benchmark" / "targets" / "duck-store" / "engage.md",
        REPO_ROOT / "plugins" / "violin_guard" / "core" / "evidence" / "findings.py",
        REPO_ROOT / "plugins" / "violin_guard" / "core" / "evidence" / "receipt_integrity.py",
    ]
    isolation_id = str(getattr(args, "target_isolation_id", "") or "").strip()
    source_commit = _git_output("rev-parse", "HEAD")
    source_dirty = bool(_git_output("status", "--porcelain"))
    if source_commit == "unknown":
        source_commit = os.environ.get("VIOLIN_SOURCE_COMMIT", "unknown").strip() or "unknown"
        dirty_override = os.environ.get("VIOLIN_SOURCE_DIRTY", "unknown").strip().casefold()
        source_dirty = dirty_override != "false"
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
            "git_commit": source_commit,
            "git_dirty": source_dirty,
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
