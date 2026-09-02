#!/usr/bin/env python3
"""Aggregate repeated benchmark engagements to account for agentic non-determinism.

A single agentic run is a noisy sample: identical frozen images score very
differently run-to-run (pass@1 varies several points even at temperature 0).
Following On Randomness in Agentic Evals (arXiv 2602.07150), a reliable
capability estimate requires multiple independent runs per task and reporting
the full envelope, not one lucky number.

This module consumes N engagement directories, re-scores each with the private
evaluator, and reports:

  * per-run confirmed-finding count,
  * mean pass@1 (the headline reliability estimate) with sample std / min / max,
  * pass@k  (optimistic: distinct challenges solved in ANY of the N runs),
  * pass^k  (pessimistic: challenges solved in EVERY run — the reliable floor),
  * per-challenge solve rate, so flaky vs. reliable classes are visible.

Only the host runs this; it requires the private golden set, exactly like
``benchmark.score``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.score import load_golden_set, score_engagement  # noqa: E402


def _confirmed_ids(result: dict[str, Any]) -> set[str]:
    return {detail["golden_id"] for detail in result.get("confirmed_details", [])}


def _classify(path: Path) -> str:
    """Classify a directory as a scored engagement, an incomplete one, or a stub.

    * ``"complete"`` — has a successful runner result, a completed manifest, or
      a legacy findings store. A valid run with zero findings is still complete.
    * ``"incomplete"`` — was initialized but is running, failed, or lacks a
      trustworthy terminal state.
    * ``"stub"`` — neither: a log tee target or unrelated directory, not an
      engagement at all.
    """
    results_path = path / "results.json"
    manifest_path = path / "run-manifest.json"
    findings_path = path / "evidence" / "findings.jsonl"
    if results_path.is_file():
        with contextlib.suppress(OSError, ValueError, json.JSONDecodeError):
            result = json.loads(results_path.read_text(encoding="utf-8"))
            runner = result.get("runner") if isinstance(result, dict) else None
            if isinstance(runner, dict) and runner.get("valid") is True:
                return "complete"
        return "incomplete"
    if manifest_path.is_file():
        with contextlib.suppress(OSError, ValueError, json.JSONDecodeError):
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(manifest, dict) and manifest.get("status") == "completed":
                return "complete"
        return "incomplete"
    if findings_path.is_file():
        return "complete"
    return "stub"


def aggregate_engagements(eng_dirs: list[Path]) -> dict[str, Any]:
    """Score every complete engagement and fold the per-run results into a distribution."""
    if not eng_dirs:
        raise ValueError("at least one engagement directory is required")
    golden_ids = [challenge["id"] for challenge in load_golden_set()]
    total = len(golden_ids)

    complete: list[Path] = []
    incomplete: list[str] = []
    incomparable: list[str] = []
    skipped: list[str] = []
    for eng_dir in eng_dirs:
        kind = _classify(eng_dir)
        if kind == "complete":
            complete.append(eng_dir)
        elif kind == "incomplete":
            incomplete.append(eng_dir.name)
        else:
            skipped.append(eng_dir.name)

    per_run: list[dict[str, Any]] = []
    confirmed_sets: list[set[str]] = []
    for eng_dir in complete:
        result = score_engagement(eng_dir.resolve())
        if (result.get("protocol_alignment") or {}).get("comparable") is False:
            incomparable.append(eng_dir.name)
            continue
        ids = _confirmed_ids(result)
        confirmed_sets.append(ids)
        per_run.append(
            {
                "run_id": eng_dir.name,
                "confirmed": result["confirmed"],
                "total": result["total"],
                "finding_score_pct": result["finding_score_pct"],
                "confirmed_ids": sorted(ids),
            }
        )

    counts = [run["confirmed"] for run in per_run]
    n = len(counts)
    mean = round(statistics.fmean(counts), 3) if n else 0.0
    std = round(statistics.stdev(counts), 3) if n > 1 else 0.0
    union = set().union(*confirmed_sets) if confirmed_sets else set()
    intersection = set(golden_ids).intersection(*confirmed_sets) if confirmed_sets else set()

    challenge_solve_rate = (
        {
            challenge_id: round(sum(challenge_id in ids for ids in confirmed_sets) / n, 3)
            for challenge_id in golden_ids
        }
        if n
        else {challenge_id: 0.0 for challenge_id in golden_ids}
    )

    return {
        "schema_version": 1,
        "runs": n,
        "total_challenges": total,
        "incomplete_engagements": incomplete,
        "incomparable_engagements": incomparable,
        "skipped_stubs": skipped,
        "per_run": per_run,
        "summary": {
            "mean_confirmed": mean,
            "mean_pass_at_1_pct": round(mean / total * 100, 1) if total else 0.0,
            "std_dev_confirmed": std,
            "min_confirmed": min(counts) if counts else 0,
            "max_confirmed": max(counts) if counts else 0,
        },
        "envelope": {
            "pass_at_k_pct": round(len(union) / total * 100, 1) if total else 0.0,
            "pass_at_k_ids": sorted(union),
            "pass_caret_k_pct": round(len(intersection) / total * 100, 1) if total else 0.0,
            "pass_caret_k_ids": sorted(intersection),
        },
        "challenge_solve_rate": challenge_solve_rate,
    }


def print_result(result: dict[str, Any]) -> None:
    summary = result["summary"]
    envelope = result["envelope"]
    print("\n" + "=" * 79)
    print("  VIOLIN BENCHMARK — MULTI-RUN AGGREGATE")
    print("=" * 79)
    print(f"RUNS         {result['runs']}")
    print(f"CHALLENGES   {result['total_challenges']}")
    for run in result["per_run"]:
        print(f"  {run['run_id']}: {run['confirmed']}/{run['total']} ({run['finding_score_pct']}%)")
    if result["incomplete_engagements"]:
        print(
            f"INCOMPLETE   {len(result['incomplete_engagements'])} (no findings: "
            f"{', '.join(result['incomplete_engagements'])})"
        )
    if result["incomparable_engagements"]:
        print(
            f"INCOMPARABLE {len(result['incomparable_engagements'])} (protocol mismatch: "
            f"{', '.join(result['incomparable_engagements'])})"
        )
    if result["skipped_stubs"]:
        print(f"SKIPPED      {len(result['skipped_stubs'])} log-tee stubs (not engagements)")
    print("-" * 79)
    print(
        f"mean pass@1  {summary['mean_pass_at_1_pct']}%  "
        f"(±{summary['std_dev_confirmed']} confirmed, "
        f"range {summary['min_confirmed']}–{summary['max_confirmed']})"
    )
    print(f"pass@k       {envelope['pass_at_k_pct']}%  (any-run optimistic bound)")
    print(f"pass^k       {envelope['pass_caret_k_pct']}%  (every-run reliable floor)")
    reliable = sorted((cid for cid, rate in result["challenge_solve_rate"].items() if rate == 1.0))
    print(f"reliable     {len(reliable)} challenge(s) solved in every run")


def generate_markdown_summary(result: dict[str, Any]) -> str:
    summary = result["summary"]
    envelope = result["envelope"]
    lines = [
        "# Violin Benchmark — Multi-Run Aggregate",
        "",
        f"**Runs:** {result['runs']} · **Challenges:** {result['total_challenges']}",
        "",
        "| Run | Confirmed | Score |",
        "|---|---:|---:|",
    ]
    for run in result["per_run"]:
        lines.append(
            f"| {run['run_id']} | {run['confirmed']}/{run['total']} | {run['finding_score_pct']}% |"
        )
    if result["incomparable_engagements"]:
        lines.extend(
            [
                "",
                "Protocol-misaligned engagements excluded: "
                + ", ".join(result["incomparable_engagements"]),
            ]
        )
    lines += [
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| mean pass@1 | {summary['mean_pass_at_1_pct']}% (±{summary['std_dev_confirmed']}) |",
        f"| pass@k (any-run) | {envelope['pass_at_k_pct']}% |",
        f"| pass^k (every-run) | {envelope['pass_caret_k_pct']}% |",
        f"| range | {summary['min_confirmed']}–{summary['max_confirmed']} confirmed |",
        "",
        "## Per-challenge solve rate",
        "",
        "| Challenge | Solve rate |",
        "|---|---:|",
    ]
    for challenge_id, rate in sorted(result["challenge_solve_rate"].items(), key=lambda kv: kv[1]):
        lines.append(f"| {challenge_id} | {rate:.0%} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate repeated benchmark engagements (non-determinism accounting)."
    )
    parser.add_argument("eng_dirs", nargs="*", type=Path, help="Engagement directories to fold in")
    parser.add_argument("--glob", type=str, help="Glob pattern over engagement directories")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()

    eng_dirs = [Path(p) for p in args.eng_dirs]
    if args.glob:
        eng_dirs.extend(sorted(REPO_ROOT.glob(args.glob)))
    if not eng_dirs:
        parser.error("provide at least one engagement directory or --glob")
    # De-duplicate preserving order.
    seen: set[str] = set()
    unique: list[Path] = []
    for path in eng_dirs:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(path)
    eng_dirs = unique

    result = aggregate_engagements(eng_dirs)
    print_result(result)
    markdown = generate_markdown_summary(result)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote {args.json_out}")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(markdown, encoding="utf-8")
        print(f"Wrote {args.markdown_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
