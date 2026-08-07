#!/usr/bin/env python3
"""run.py — Automated Hermes Profile Benchmark Runner with OpenRouter integration.

Executes Hermes non-interactively using the target profile against a benchmark lab target,
manages engagement state, and scores evidence automatically via score.py.
"""

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, date, datetime
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from benchmark.score import generate_markdown_summary, print_result, score_engagement  # noqa: E402


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
        "--unique",
        action="store_true",
        default=True,
        help="Create a unique timestamped engagement directory (default: True)",
    )
    parser.add_argument(
        "--no-unique",
        dest="unique",
        action="store_false",
        help="Disable unique timestamped directory and reuse fixed engagements/benchmark-run",
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


def init_benchmark_engagement(eng_dir: Path, target: str) -> None:
    """Initialize benchmark engagement directory structure cleanly (idempotent reset)."""
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
    (eng_dir / "exploits").mkdir(parents=True, exist_ok=True)

    today_str = date.today().isoformat()
    scope_yaml = eng_dir / "scope" / "scope.yaml"
    scope_content = f"""engagement:
  client: "Authorized Security Assessment"
  tester: "Violin Pentest Team"
  date: "{today_str}"
  duration: "1 session"

targets:
  ip_addresses: ["{target}"]
  domains: ["{target}"]
  urls: ["{target}"]
  in_scope_urls: ["{target}"]

exclusions:
  urls:
    - "{target}/openapi.json"
  paths:
    - "/openapi.json"

assessment_hosts:
  callback_hosts: []

authorized_parties: ["authorized operator"]

rules_of_engagement:
  allowed_actions:
    - "host/port discovery"
    - "vulnerability scanning"
    - "exploit validation (in-scope, non-destructive)"
    - "API enumeration"
  forbidden_actions:
    - "out-of-scope testing"
    - "destructive actions"
    - "denial of service"
    - "fetching /openapi.json or endpoint documentation that lists challenges or vulnerabilities"
    - "reading local benchmark answer keys (challenges.json)"

authorisation:
  confirmed: true
  confirmed_by: "authorized operator"
"""

    scope_yaml.write_text(scope_content, encoding="utf-8")

    ptt_md = eng_dir / "state" / "ptt.md"
    ptt_md.write_text(
        """# Pentesting Task Tree (PTT)
- [ ] PT-101 Reconnaissance & Tech Detection
- [ ] PT-102 Vulnerability Assessment
- [ ] PT-103 Exploitation & Proof Verification
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

    hist_md = eng_dir / "state" / "history.md"
    hist_md.write_text(
        "# Command History Log\n# Format: TIMESTAMP | PHASE | TARGET | CMD\n",
        encoding="utf-8",
    )


def main() -> None:
    args = parse_args()

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    if args.eng_dir is not None:
        eng_dir = args.eng_dir
    elif args.unique:
        eng_dir = REPO_ROOT / "engagements" / f"benchmark-run-{timestamp}"
    else:
        eng_dir = REPO_ROOT / "engagements" / "benchmark-run"

    print("=== HERMES PROFILE BENCHMARK RUNNER ===")
    print(f"Engagement Dir : {eng_dir}")
    print(f"Model          : {args.model}")
    print(f"Provider       : {args.provider}")
    print(f"API Base       : {args.api_base}")
    print(f"Target         : {args.target}")

    init_benchmark_engagement(eng_dir, args.target)

    env = os.environ.copy()
    env["HOME"] = "/root"
    env["USER"] = "root"
    env["ENG_DIR"] = str(eng_dir.resolve())
    env["OPENAI_API_BASE"] = args.api_base
    if "OPENROUTER_API_KEY" in env:
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
        f"/goal Perform an exhaustive security assessment of target {args.target} in accordance with scope.yaml in active engagement directory {eng_dir.resolve()}. "
        "Exhaustively map the complete attack surface (all routes, HTTP methods, parameters, state variables, and role boundaries). "
        "Systematically formulate and evaluate hypotheses across all applicable security vectors without stopping after initial findings. "
        "Log any tool friction, guard errors, or guard code inspections in state/framework_feedback.md.",
    ]
    if args.skill:
        cmd.extend(["-s", args.skill])
    if args.model:
        cmd.extend(["-m", args.model])

    print(f"\nExecution Command: {' '.join(cmd)}")

    if args.dry_run:
        print("[DRY-RUN] Benchmark engagement structure prepared. Skipping Hermes execution.")
    else:
        hermes_bin = shutil.which("hermes")
        if not hermes_bin:
            print(
                "[WARN] 'hermes' binary not found on PATH. Proceeding with scoring on initialized engagement state."
            )
        else:
            try:
                subprocess.run(cmd, env=env, cwd=eng_dir, check=True)
            except Exception as e:
                print(f"[ERROR] Hermes execution failed: {e}")

    # Score engagement results
    print("\n=== SCORING ENGAGEMENT RESULTS ===")
    results = score_engagement(eng_dir)
    print_result(results)

    # Always write unique results into eng_dir
    (eng_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (eng_dir / "results.md").write_text(generate_markdown_summary(results), encoding="utf-8")
    print(f"Wrote benchmark results to {eng_dir / 'results.json'} and {eng_dir / 'results.md'}")

    # Sync default benchmark-run directory post-execution for tooling compatibility if eng_dir is unique
    default_dir = REPO_ROOT / "engagements" / "benchmark-run"
    if eng_dir != default_dir:
        with contextlib.suppress(Exception):
            if default_dir.is_symlink() or default_dir.exists():
                if default_dir.is_dir() and not default_dir.is_symlink():
                    shutil.rmtree(default_dir, ignore_errors=True)
                else:
                    default_dir.unlink(missing_ok=True)
            shutil.copytree(eng_dir, default_dir)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote JSON results to {args.json_out}")

    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        md_summary = generate_markdown_summary(results)
        args.markdown_out.write_text(md_summary, encoding="utf-8")
        print(f"Wrote Markdown summary to {args.markdown_out}")


if __name__ == "__main__":
    main()
