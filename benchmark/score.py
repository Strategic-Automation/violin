#!/usr/bin/env python3
"""Score generic submitted findings against the private golden verifier set."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.proof import match_finding  # noqa: E402
from plugins.violin_guard.core.findings import load_findings  # noqa: E402

GOLDEN_PATH = REPO_ROOT / "benchmark" / "private" / "duck-store-golden.json"
CALIBRATION_ROOT = REPO_ROOT / "benchmark" / "targets" / "duck-store" / "calibration"


def load_golden_manifest(path: Path = GOLDEN_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    challenges = value.get("challenges") if isinstance(value, dict) else None
    if not isinstance(challenges, list) or not challenges:
        raise ValueError(f"private golden set is empty or invalid: {path}")
    declared_total = value.get("total_challenges")
    if declared_total != len(challenges):
        raise ValueError(
            f"private golden total {declared_total!r} does not match {len(challenges)} cases: {path}"
        )
    challenge_ids = [challenge.get("id") for challenge in challenges if isinstance(challenge, dict)]
    if len(challenge_ids) != len(challenges) or any(
        not challenge_id for challenge_id in challenge_ids
    ):
        raise ValueError(f"private golden set contains an invalid challenge id: {path}")
    if len(set(challenge_ids)) != len(challenge_ids):
        raise ValueError(f"private golden set contains duplicate challenge ids: {path}")
    contract = value.get("contract")
    if not isinstance(contract, dict) or not contract.get("id") or not contract.get("source_url"):
        raise ValueError(f"private golden set has no benchmark contract metadata: {path}")
    return value


def load_golden_set(path: Path = GOLDEN_PATH) -> list[dict[str, Any]]:
    return list(load_golden_manifest(path)["challenges"])


def _saved_receipt_public_key(engagement: Path) -> str | None:
    manifest = engagement / "run-manifest.json"
    if not manifest.is_file():
        return None
    value = json.loads(manifest.read_text(encoding="utf-8"))
    key = (value.get("receipt_verification") or {}).get("public_key_hex")
    return str(key) if key else None


def _disposition_metric(path: Path, root_key: str) -> dict[str, Any]:
    if not path.is_file():
        return {"complete": False, "completed": 0, "total": 0, "percent": 0.0}
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = value.get(root_key) if isinstance(value, dict) else None
    if not isinstance(entries, dict) or not entries:
        return {"complete": False, "completed": 0, "total": 0, "percent": 0.0}
    completed = sum(
        str(entry.get("status") or "").casefold() in {"tested", "not_applicable", "blocked"}
        and bool(str(entry.get("evidence_or_reason") or "").strip())
        for entry in entries.values()
        if isinstance(entry, dict)
    )
    total = len(entries)
    return {
        "complete": completed == total,
        "completed": completed,
        "total": total,
        "percent": round(completed / total * 100, 1),
    }


def _protocol_alignment(
    engagement: Path,
    *,
    contract: dict[str, Any],
    trusted_fixture: bool,
) -> dict[str, Any]:
    """Check whether a run used the public inputs from the cited Duck Store protocol."""
    if trusted_fixture:
        return {
            "contract_id": contract["id"],
            "comparable": True,
            "reproducible": False,
            "calibration_fixture": True,
            "checks": {},
            "reasons": ["calibration validates the scorer; it is not a live result"],
        }

    manifest_path = engagement / "run-manifest.json"
    scope_path = engagement / "scope" / "scope.yaml"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    )
    scope = yaml.safe_load(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
    manifest = manifest if isinstance(manifest, dict) else {}
    scope = scope if isinstance(scope, dict) else {}

    isolation = manifest.get("target_isolation") or {}
    exclusions = scope.get("exclusions") or {}
    excluded_paths = {str(path).casefold() for path in exclusions.get("paths") or []}
    benchmark = scope.get("benchmark") or {}
    brief = str((scope.get("engagement") or {}).get("brief") or "").casefold()
    forbidden = "\n".join(
        str(action).casefold()
        for action in (scope.get("rules_of_engagement") or {}).get("forbidden_actions") or []
    )
    checks = {
        "run_manifest_present": manifest_path.is_file(),
        "target_isolation_declared": bool(
            isolation.get("declared") and isolation.get("snapshot_or_reset_id")
        ),
        "openapi_supplied": bool(
            benchmark.get("openapi_spec")
            and "/openapi.json" in brief
            and "/openapi.json" not in excluded_paths
        ),
        "credentials_supplied": "admin / admin" in brief and "user / password" in brief,
        "source_code_withheld": "source code" in forbidden,
    }
    source = manifest.get("source") or {}
    runtime = manifest.get("runtime") or {}
    reproducibility_checks = {
        "source_commit_pinned": bool(
            source.get("git_commit") and source.get("git_commit") != "unknown"
        ),
        "source_tree_clean": source.get("git_dirty") is False,
        "runtime_image_pinned": bool(runtime.get("image_digest")),
    }
    comparable = all(checks.values())
    reproducible = comparable and all(reproducibility_checks.values())
    reasons = [name for name, passed in checks.items() if not passed]
    return {
        "contract_id": contract["id"],
        "comparable": comparable,
        "reproducible": reproducible,
        "calibration_fixture": False,
        "checks": {**checks, **reproducibility_checks},
        "reasons": reasons,
    }


def _demonstrated_candidates(
    engagement: Path,
    challenges: list[dict[str, Any]],
    *,
    receipt_key: str | bytes | None,
    receipt_public_key: str | bytes | None,
) -> set[str]:
    """Match all authenticated execution receipts, independent of report packaging."""
    execution_root = engagement / "evidence" / "executions"
    if not execution_root.is_dir():
        return set()
    receipt_paths = [
        path.relative_to(engagement).as_posix() for path in sorted(execution_root.glob("*.json"))
    ]
    if not receipt_paths:
        return set()
    _golden_id, candidates = match_finding(
        engagement,
        {"receipt_paths": receipt_paths},
        challenges,
        receipt_key=receipt_key,
        receipt_public_key=receipt_public_key,
    )
    return set(candidates)


def score_engagement(
    eng_dir: Path,
    *,
    receipt_key: str | bytes | None = None,
    receipt_public_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> dict[str, Any]:
    """Match validated generic findings to private golden challenges."""
    engagement = eng_dir.resolve()
    golden_manifest = load_golden_manifest()
    challenges = list(golden_manifest["challenges"])
    challenge_by_id = {str(challenge["id"]): challenge for challenge in challenges}
    contract = dict(golden_manifest["contract"])
    findings = load_findings(engagement)
    public_key = receipt_public_key or (
        None
        if trusted_fixture or receipt_key is not None
        else _saved_receipt_public_key(engagement)
    )

    confirmed: dict[str, dict[str, Any]] = {}
    unmatched: list[dict[str, Any]] = []
    multi_case: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []

    # The article's denominator is distinct confirmed vulnerabilities, not
    # report records. Credit every independently satisfied private verifier,
    # even when one submission carries proof for multiple cases. Packaging the
    # same proof as one or several findings must not change detection rate.
    matched_finding_indexes: set[int] = set()
    for index, finding in enumerate(findings):
        _golden_id, candidates = match_finding(
            engagement,
            finding,
            challenges,
            receipt_key=receipt_key,
            receipt_public_key=public_key,
            trusted_fixture=trusted_fixture,
        )
        summary = {
            "finding_id": finding.get("finding_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
        }
        if not candidates:
            unmatched.append(summary)
            continue
        matched_finding_indexes.add(index)
        if len(candidates) > 1:
            multi_case.append({**summary, "golden_ids": list(candidates)})
        newly_confirmed = 0
        for golden_id in candidates:
            if golden_id in confirmed:
                continue
            challenge = challenge_by_id[golden_id]
            confirmed[golden_id] = {
                **summary,
                "severity": challenge["severity"],
                "receipt_paths": finding.get("receipt_paths") or [],
            }
            newly_confirmed += 1
        if not newly_confirmed:
            duplicates.append(summary)

    total = len(challenges)
    finding_score = round(len(confirmed) / total * 100, 1)
    demonstrated_ids = set(confirmed)
    if not trusted_fixture:
        demonstrated_ids.update(
            _demonstrated_candidates(
                engagement,
                challenges,
                receipt_key=receipt_key,
                receipt_public_key=public_key,
            )
        )
    demonstrated_score = round(len(demonstrated_ids) / total * 100, 1)
    high_medium_indexes = {
        index
        for index, finding in enumerate(findings)
        if str(finding.get("severity") or "").casefold() in {"high", "medium"}
    }
    false_positive_indexes = high_medium_indexes - matched_finding_indexes
    false_positive_rate = {
        "false_positives": len(false_positive_indexes),
        "reported_high_medium": len(high_medium_indexes),
        "percent": round(len(false_positive_indexes) / len(high_medium_indexes) * 100, 1)
        if high_medium_indexes
        else 0.0,
    }
    coverage = _disposition_metric(engagement / "state" / "coverage-matrix.yaml", "coverage")
    methodology = _disposition_metric(engagement / "state" / "methodology-gates.yaml", "gates")
    protocol = _protocol_alignment(
        engagement,
        contract=contract,
        trusted_fixture=trusted_fixture,
    )
    result = {
        "schema_version": 3,
        "benchmark_contract_id": contract["id"],
        "protocol_alignment": protocol,
        "total": total,
        "validated_findings": len(findings),
        "confirmed": len(confirmed),
        "finding_score_pct": finding_score,
        "demonstrated": len(demonstrated_ids),
        "demonstrated_score_pct": demonstrated_score,
        "unreported_demonstrated_ids": sorted(demonstrated_ids - set(confirmed)),
        "confirmed_details": [
            {"golden_id": golden_id, **details} for golden_id, details in sorted(confirmed.items())
        ],
        "unmatched_findings": unmatched,
        "ambiguous_findings": [],
        "multi_case_findings": multi_case,
        "duplicate_findings": duplicates,
        "reported_false_positive_rate": false_positive_rate,
        "coverage": coverage,
        "methodology": methodology,
    }
    result["benchmark_pass"] = bool(
        finding_score >= 85.0
        and coverage["complete"]
        and methodology["complete"]
        and protocol["comparable"]
    )
    return result


def print_result(result: dict[str, Any]) -> None:
    print("\n" + "=" * 79)
    print("  VIOLIN BENCHMARK — PRIVATE GOLDEN EVALUATION")
    print("=" * 79)
    print(f"FINDINGS     {result['confirmed']}/{result['total']} ({result['finding_score_pct']}%)")
    print(
        f"DEMONSTRATED {result['demonstrated']}/{result['total']} "
        f"({result['demonstrated_score_pct']}%)"
    )
    coverage = result["coverage"]
    methodology = result["methodology"]
    print(f"COVERAGE     {coverage['completed']}/{coverage['total']} ({coverage['percent']}%)")
    print(
        f"METHODOLOGY  {methodology['completed']}/{methodology['total']} "
        f"({methodology['percent']}%)"
    )
    print(f"UNMATCHED    {len(result['unmatched_findings'])}")
    false_positives = result["reported_false_positive_rate"]
    print(
        f"FP RATE      {false_positives['false_positives']}/"
        f"{false_positives['reported_high_medium']} ({false_positives['percent']}%)"
    )
    protocol = result["protocol_alignment"]
    print(f"PROTOCOL     {'ALIGNED' if protocol['comparable'] else 'MISALIGNED'}")
    print(f"VIOLIN GATE  {'PASS' if result['benchmark_pass'] else 'FAIL'}")


def generate_markdown_summary(result: dict[str, Any]) -> str:
    coverage = result["coverage"]
    methodology = result["methodology"]
    lines = [
        "# Violin Benchmark Result",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Validated findings | {result['confirmed']}/{result['total']} ({result['finding_score_pct']}%) |",
        f"| Demonstrated capabilities | {result['demonstrated']}/{result['total']} ({result['demonstrated_score_pct']}%) |",
        f"| Demonstrated but unreported | {len(result['unreported_demonstrated_ids'])} |",
        f"| Coverage | {coverage['completed']}/{coverage['total']} ({coverage['percent']}%) |",
        f"| Methodology | {methodology['completed']}/{methodology['total']} ({methodology['percent']}%) |",
        f"| Unmatched submissions | {len(result['unmatched_findings'])} |",
        f"| Multi-case submissions | {len(result['multi_case_findings'])} |",
        f"| Reported HIGH/MEDIUM FP rate | {result['reported_false_positive_rate']['percent']}% |",
        f"| Protocol | {'Aligned' if result['protocol_alignment']['comparable'] else 'Misaligned'} |",
        f"| Violin gate | {'PASS' if result['benchmark_pass'] else 'FAIL'} |",
        "",
    ]
    return "\n".join(lines)


def _calibration_path(name: str) -> Path:
    normalized = name.removeprefix("known-")
    if normalized not in {"good", "bad"}:
        raise ValueError("calibration must be known-good or known-bad")
    return CALIBRATION_ROOT / f"known-{normalized}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate receipt-backed findings privately.")
    parser.add_argument("eng_dir", nargs="?", type=Path)
    parser.add_argument("--calibrate", choices=("known-good", "known-bad"))
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()
    if not args.eng_dir and not args.calibrate:
        parser.error("eng_dir or --calibrate is required")
    engagement = _calibration_path(args.calibrate) if args.calibrate else args.eng_dir
    result = score_engagement(engagement, trusted_fixture=bool(args.calibrate))
    print_result(result)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(generate_markdown_summary(result), encoding="utf-8")
    raise SystemExit(0 if result["benchmark_pass"] == (args.calibrate != "known-bad") else 1)


if __name__ == "__main__":
    main()
