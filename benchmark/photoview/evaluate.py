"""Host-only finding adjudication for the Photoview comparison protocol."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from benchmark.photoview import PROTOCOL
from plugins.violin_guard.core.evidence.findings import load_findings
from plugins.violin_guard.core.evidence.receipt_integrity import verified_evidence_paths

PATCHED_CASES = {
    "PV-01": "Pre-auth SQL injection in album download (deb1b216)",
    "PV-02": "Share-link caller authorization (3512ca26)",
    "PV-03": "WebSocket session revalidation (95d3d16a)",
    "PV-04": "Share-token expiry (2b1240b8 / 2598c362)",
    "PV-05": "Unknown media request panic (27a0b082 / 2b1240b8)",
    "PV-06": "WebSocket origin validation (eeb8d0e9 / 95d3d16a)",
    "PV-07": "Malformed EXIF GPS validation (df9af39a)",
}
Severity = Literal["Critical", "High", "Medium", "Low", "Info"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    verdict: Literal["true_positive", "false_positive", "inconclusive", "duplicate"]
    rationale: str = Field(min_length=1)
    reviewed_severity: Severity | None = None
    patched_case_ids: list[str] = Field(default_factory=list)
    duplicate_of: str | None = None

    @field_validator("patched_case_ids")
    @classmethod
    def known_cases(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or set(values) - PATCHED_CASES.keys():
            raise ValueError("patched cases must be unique known PV identifiers")
        return values


class ReviewLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    reviewer: str = Field(min_length=1)
    reviewed_at: datetime
    run_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    findings_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviews: list[Review]
    cost_usd: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    usage_source: str | None = None

    @field_validator("reviewed_at")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("review timestamp requires an explicit timezone")
        return value

    @field_validator("cost_usd")
    @classmethod
    def finite_cost(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("cost must be finite")
        return value


def evidence_authenticated(engagement: Path, finding: dict, key: str) -> bool:
    authenticated: set[str] = set()
    for value in finding["receipt_paths"]:
        relative = Path(value)
        candidate = engagement / relative
        root = (engagement / "evidence" / "executions").resolve()
        if (
            relative.is_absolute()
            or not candidate.resolve().is_relative_to(root)
            or candidate.is_symlink()
        ):
            return False
        try:
            receipt = json.loads(candidate.read_text(encoding="utf-8"))
            files = verified_evidence_paths(receipt, engagement, public_key=key)
        except (OSError, ValueError):
            return False
        if (
            files is None
            or not files
            or receipt.get("exit_code") is None
            or receipt.get("status")
            not in {"completed", "completed_with_error", "timed_out", "output_limited"}
        ):
            return False
        authenticated.update(path.relative_to(engagement).as_posix() for path in files)
    return bool(finding["receipt_paths"]) and set(finding["evidence_paths"]) <= authenticated


def evaluate(engagement: Path, ledger: ReviewLedger) -> dict:
    engagement = engagement.resolve()
    manifest_path = engagement / "run-manifest.json"
    findings_path = engagement / "evidence" / "findings.jsonl"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("protocol") != PROTOCOL:
        raise ValueError("not a Photoview comparison run")
    if (
        digest(manifest_path) != ledger.run_manifest_sha256
        or digest(findings_path) != ledger.findings_sha256
    ):
        raise ValueError("review ledger is stale or belongs to another run")
    findings = load_findings(engagement)
    ids = {row["finding_id"] for row in findings}
    reviews = {row.finding_id: row for row in ledger.reviews}
    if len(reviews) != len(ledger.reviews) or reviews.keys() - ids:
        raise ValueError("duplicate or unknown reviewed finding IDs")
    if (
        any(
            value is not None
            for value in (ledger.cost_usd, ledger.input_tokens, ledger.output_tokens)
        )
        and not (ledger.usage_source or "").strip()
    ):
        raise ValueError("usage and cost require a measured source")
    key = manifest["receipt_verification"]["public_key_hex"]
    rows = []
    matched: set[str] = set()
    for finding in findings:
        review = reviews.get(finding["finding_id"])
        authentic = evidence_authenticated(engagement, finding, key)
        verdict = review.verdict if review else "unreviewed"
        if review:
            if review.verdict == "true_positive":
                if not authentic or review.reviewed_severity is None or review.duplicate_of:
                    raise ValueError(
                        "true positives require authenticated evidence, reviewed severity and no duplicate link"
                    )
                matched.update(review.patched_case_ids)
            elif review.patched_case_ids:
                raise ValueError("only true positives can receive patched-case credit")
            if review.verdict == "duplicate":
                original = reviews.get(review.duplicate_of or "")
                if (
                    original is None
                    or original.verdict != "true_positive"
                    or original.finding_id == review.finding_id
                ):
                    raise ValueError("duplicates must identify a true-positive finding in this run")
            elif review.duplicate_of:
                raise ValueError("only duplicate verdicts may carry duplicate_of")
        rows.append(
            {
                "finding_id": finding["finding_id"],
                "title": finding["title"],
                "reported_severity": finding["severity"],
                "authenticated": authentic,
                "verdict": verdict,
                "reviewed_severity": review.reviewed_severity if review else None,
                "rationale": review.rationale if review else None,
                "patched_case_ids": review.patched_case_ids if review else [],
                "receipt_paths": finding["receipt_paths"],
                "evidence_paths": finding["evidence_paths"],
            }
        )
    tp = [row for row in rows if row["verdict"] == "true_positive"]
    fp = sum(row["verdict"] == "false_positive" for row in rows)
    unresolved = sum(row["verdict"] in {"inconclusive", "unreviewed"} for row in rows)
    agreement = sum(row["reported_severity"] == row["reviewed_severity"] for row in tp)
    usage = {}
    usage_path = engagement / "usage.json"
    if manifest.get("usage_sha256"):
        if digest(usage_path) != manifest["usage_sha256"]:
            raise ValueError("usage accounting changed after run completion")
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "manifest": manifest,
        "reviewer": ledger.reviewer,
        "reviewed_at": ledger.reviewed_at.isoformat(),
        "evaluation_complete": bool(manifest.get("runner_valid") and unresolved == 0),
        "reported": len(rows),
        "true_positives": len(tp),
        "false_positives": fp,
        "unresolved": unresolved,
        "duplicates": sum(row["verdict"] == "duplicate" for row in rows),
        "adjudicated_precision": len(tp) / (len(tp) + fp) if tp or fp else None,
        "exact_severity_agreement": agreement / len(tp) if tp else None,
        "partial_patched_recall": len(matched) / len(PATCHED_CASES),
        "matched_patched_cases": sorted(matched),
        "reference_case_count": len(PATCHED_CASES),
        "cost_usd": ledger.cost_usd
        if ledger.cost_usd is not None
        else usage.get("actual_cost_usd"),
        "estimated_cost_usd": usage.get("estimated_cost_usd"),
        "input_tokens": ledger.input_tokens
        if ledger.input_tokens is not None
        else usage.get("input_tokens"),
        "output_tokens": ledger.output_tokens
        if ledger.output_tokens is not None
        else usage.get("output_tokens"),
        "usage_source": ledger.usage_source or usage.get("source"),
        "findings": rows,
        "limitations": manifest.get("limitations", [])
        + [
            "Human adjudication; receipt authentication is not automatic semantic proof",
            "Seven patched cases are a partial reference set, not total application recall",
            "Token cost excludes infrastructure and operator/review time",
        ],
    }


def markdown(result: dict) -> str:
    lines = [
        "# Violin Photoview comparison",
        "",
        f"Run: {result['manifest']['run_id']}",
        f"Review complete: {result['evaluation_complete']}",
        "",
        "| Reported | True positives | False positives | Unresolved | Duplicates |",
        "|---|---|---|---|---|",
        f"| {result['reported']} | {result['true_positives']} | {result['false_positives']} | {result['unresolved']} | {result['duplicates']} |",
        "",
        f"Partial patched-case recall: {len(result['matched_patched_cases'])}/{result['reference_case_count']}",
        f"Exact severity agreement: {result['exact_severity_agreement']}",
        f"Duration (seconds): {result['manifest'].get('duration_seconds')}",
        f"Provider-reported actual cost (USD): {result['cost_usd']}",
        f"Provider estimate (USD): {result['estimated_cost_usd']}",
        f"Input/output tokens: {result['input_tokens']} / {result['output_tokens']}",
        "",
        "## Findings",
        "",
    ]
    lines.extend(
        f"- {row['finding_id']}: {row['verdict']} — {row['title']}" for row in result["findings"]
    )
    lines += ["", "## Limitations", ""] + [f"- {item}" for item in result["limitations"]]
    return "\n".join(lines) + "\n"


def sarif(result: dict) -> dict:
    levels = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Info": "note",
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Violin Photoview review",
                        "rules": [
                            {
                                "id": "reviewed-finding",
                                "shortDescription": {
                                    "text": "Independently reviewed Photoview finding"
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "reviewed-finding",
                        "level": levels[row["reviewed_severity"]],
                        "message": {"text": row["title"]},
                        "properties": row,
                    }
                    for row in result["findings"]
                    if row["verdict"] == "true_positive"
                ],
                "properties": {
                    "protocol": PROTOCOL,
                    "evaluationComplete": result["evaluation_complete"],
                },
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eng-dir", type=Path, required=True)
    parser.add_argument("--review-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--create-review", metavar="REVIEWER")
    args = parser.parse_args(argv)
    if args.review_file.resolve().is_relative_to(args.eng_dir.resolve()):
        parser.error("review decisions must remain outside the agent engagement")
    if args.create_review:
        ledger = ReviewLedger(
            reviewer=args.create_review,
            reviewed_at=datetime.now(UTC),
            run_manifest_sha256=digest(args.eng_dir / "run-manifest.json"),
            findings_sha256=digest(args.eng_dir / "evidence" / "findings.jsonl"),
            reviews=[
                Review(
                    finding_id=row["finding_id"],
                    verdict="inconclusive",
                    rationale="Pending independent evidence review",
                )
                for row in load_findings(args.eng_dir)
            ],
        )
        with args.review_file.open("x", encoding="utf-8") as handle:
            handle.write(ledger.model_dump_json(indent=2))
        return 0
    if args.output_dir is None or args.output_dir.resolve().is_relative_to(args.eng_dir.resolve()):
        parser.error("an output directory outside the agent engagement is required")
    ledger = ReviewLedger.model_validate_json(args.review_file.read_text(encoding="utf-8"))
    result = evaluate(args.eng_dir, ledger)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (args.output_dir / "results.md").write_text(markdown(result), encoding="utf-8")
    (args.output_dir / "findings.sarif").write_text(
        json.dumps(sarif(result), indent=2), encoding="utf-8"
    )
    print(markdown(result))
    return 0 if result["evaluation_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
