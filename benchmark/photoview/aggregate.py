"""Aggregate explicit compatible Photoview results, retaining failures."""

from __future__ import annotations

import argparse
import glob
import json
import statistics
from pathlib import Path

from benchmark.photoview import PROTOCOL
from benchmark.photoview.evaluate import PATCHED_CASES

COMPATIBILITY_FIELDS = (
    "protocol",
    "target_source_commit",
    "target_source_sha256",
    "target_image",
    "database_image",
    "runtime_image",
    "violin_commit",
    "violin_dirty",
    "model",
    "provider",
    "api_base",
    "dataset",
)


def aggregate(paths: list[Path]) -> dict:
    if not paths or len({path.resolve() for path in paths}) != len(paths):
        raise ValueError("supply distinct nonempty run result paths")
    rows = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    baseline = rows[0]["manifest"]
    identity = tuple(baseline[field] for field in COMPATIBILITY_FIELDS)
    if baseline["protocol"] != PROTOCOL:
        raise ValueError("not a Photoview protocol")
    runs, fixtures = set(), set()
    for row in rows:
        manifest = row["manifest"]
        if tuple(manifest[field] for field in COMPATIBILITY_FIELDS) != identity:
            raise ValueError("cannot mix protocols, revisions, images, datasets or models")
        if manifest["run_id"] in runs or manifest["fixture_id"] in fixtures:
            raise ValueError("independent runs require distinct run and reset identities")
        runs.add(manifest["run_id"])
        fixtures.add(manifest["fixture_id"])
    counts = [row["true_positives"] for row in rows]
    durations = [row["manifest"].get("duration_seconds") for row in rows]
    cost_rows = [row.get("cost_usd") for row in rows]
    known_costs = [value for value in cost_rows if value is not None]
    estimate_rows = [row.get("estimated_cost_usd") for row in rows]
    known_estimates = [value for value in estimate_rows if value is not None]
    matched_by_case = {
        case: sum(case in row.get("matched_patched_cases", []) for row in rows)
        for case in PATCHED_CASES
    }
    return {
        "protocol": PROTOCOL,
        "runs": len(rows),
        "completed_evaluations": sum(row["evaluation_complete"] for row in rows),
        "failed_runners": sum(not row["manifest"]["runner_valid"] for row in rows),
        "incomplete_evaluations": sum(not row["evaluation_complete"] for row in rows),
        "mean_observed_true_positives": statistics.mean(counts),
        "stdev_observed_true_positives": statistics.stdev(counts) if len(counts) > 1 else 0,
        "mean_partial_patched_recall": statistics.mean(
            row["partial_patched_recall"] for row in rows
        ),
        "mean_false_positives": statistics.mean(row["false_positives"] for row in rows),
        "mean_duration_seconds": statistics.mean(
            [value for value in durations if value is not None]
        )
        if any(value is not None for value in durations)
        else None,
        "total_known_actual_cost_usd": sum(known_costs),
        "runs_with_unknown_actual_cost": len(cost_rows) - len(known_costs),
        "total_provider_estimated_cost_usd": sum(known_estimates),
        "runs_with_unknown_provider_estimate": len(estimate_rows) - len(known_estimates),
        "total_input_tokens": sum(row.get("input_tokens") or 0 for row in rows),
        "total_output_tokens": sum(row.get("output_tokens") or 0 for row in rows),
        "patched_case_hits": matched_by_case,
        "patched_cases_not_observed": sorted(
            case for case, hits in matched_by_case.items() if hits == 0
        ),
        "per_run": [
            {
                "path": str(path),
                "run_id": row["manifest"]["run_id"],
                "runner_valid": row["manifest"]["runner_valid"],
                "evaluation_complete": row["evaluation_complete"],
                "true_positives": row["true_positives"],
                "false_positives": row["false_positives"],
                "partial_patched_recall": row["partial_patched_recall"],
            }
            for path, row in zip(paths, rows, strict=True)
        ],
        "publishable_provenance": bool(
            not baseline["violin_dirty"]
            and baseline["violin_commit"] != "unknown"
            and all(row["evaluation_complete"] for row in rows)
        ),
        "limitations": [
            "Observed means include every supplied run, including failures",
            "Partial patched-case recall is not total application recall",
            "No arbitrary pass threshold or Duck Store release gate is applied",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--glob", required=True, help="One revision, model and protocol only")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = aggregate([Path(value) for value in sorted(glob.glob(args.glob))])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
