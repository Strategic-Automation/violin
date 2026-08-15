#!/usr/bin/env python3
"""Heuristic proof audit backed by the benchmark's shared proof evaluator."""

from __future__ import annotations

import contextlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from benchmark.indexer import collect_engagement_artifacts
from benchmark.proof import (
    broken_evidence_references,
    evaluate_technical_proof,
    finding_confirmed_challenge_ids,
    parse_findings,
    parse_hypotheses,
)

BENCHMARK_DIR = Path(__file__).resolve().parent
CHALLENGES_PATH = BENCHMARK_DIR / "targets" / "duck-store" / "challenges.json"

_KNOWN_STATE_ARTIFACTS = {
    "checkpoint.json",
    "counts.json",
    "coverage-matrix.yaml",
    "framework_feedback.md",
    "heartbeat.json",
    "history.md",
    "phase-summary.md",
    "ptt.md",
    "report.md",
    "retrospective.md",
    "semantic-progress.json",
    "session.json",
    "skills.json",
    "sync.json",
}


def load_challenges() -> list[dict[str, Any]]:
    if not CHALLENGES_PATH.exists():
        return []
    with contextlib.suppress(OSError, json.JSONDecodeError):
        payload = json.loads(CHALLENGES_PATH.read_text(encoding="utf-8"))
        return list(payload.get("challenges", []))
    return []


def _validated_blocks(hypotheses_text: str) -> list[str]:
    return [
        block
        for block in re.split(r"\n(?=### H-\d+:)", hypotheses_text)
        if re.search(r"(?im)^(?:[-*]\s*)?\*\*Status:\*\*\s*Validated\s*$", block)
    ]


def _block_cites_bundle(eng_dir: Path, block: str, challenge_id: str, paths: set[str]) -> bool:
    linked = re.search(r"(?im)^(?:[-*]\s*)?\*\*Linked challenges:\*\*\s*(.+)$", block)
    challenge_linked = bool(
        linked and challenge_id in {item.strip() for item in linked.group(1).split(",")}
    )
    evidence_linked = any(Path(path).name in block for path in paths)
    finding_match = re.search(r"(?im)^(?:[-*]\s*)?\*\*Linked findings:\*\*\s*(.+)$", block)
    finding_ids = (
        {item.strip().upper() for item in finding_match.group(1).split(",")}
        if finding_match
        else set()
    )
    canonical = []
    for finding_id in finding_ids:
        finding = eng_dir / "evidence" / "findings" / f"{finding_id}.md"
        if finding.is_file():
            canonical.append(finding.read_text(encoding="utf-8", errors="replace"))
    finding_linked = any(
        Path(path).name in finding_text for path in paths for finding_text in canonical
    )
    return (challenge_linked or evidence_linked) and finding_linked


def audit_framework_friction_and_bugs(artifacts: dict[str, Any]) -> dict[str, Any]:
    """Audit recorded friction and state layout without treating state as proof."""
    audit: dict[str, list[Any]] = {
        "logged_feedback_items": [],
        "syntax_errors_in_history": [],
        "guard_blocks": [],
        "schema_drift_warnings": [],
    }
    for line in artifacts.get("feedback_text", "").splitlines():
        if not line.startswith("| 20") and not line.startswith("|20"):
            continue
        parts = [part.strip() for part in line.split("|")[1:-1]]
        if len(parts) >= 3:
            audit["logged_feedback_items"].append(
                {
                    "date": parts[0],
                    "category": parts[1],
                    "issue": parts[2],
                    "workaround": parts[3] if len(parts) > 3 else "",
                    "prevention": parts[4] if len(parts) > 4 else "",
                }
            )

    for line in artifacts.get("history_text", "").splitlines():
        lowered = line.lower()
        if any(
            marker in lowered
            for marker in ("syntax error", "unterminated quoted string", "command not found")
        ):
            audit["syntax_errors_in_history"].append(line.strip())
        if "block:" in lowered or "denied" in lowered or "forbidden" in lowered:
            audit["guard_blocks"].append(line.strip())

    hypotheses_text = artifacts.get("hypotheses_text", "")
    if hypotheses_text and not re.search(r"### H-\d+:", hypotheses_text):
        audit["schema_drift_warnings"].append(
            "hypotheses.md has content but no canonical ### H-XXX blocks"
        )

    unexpected_state = [
        item["path"]
        for item in artifacts.get("state_files", [])
        if Path(item["path"]).name not in _KNOWN_STATE_ARTIFACTS
        and not Path(item["path"]).name.endswith(".lock")
    ]
    if unexpected_state:
        audit["schema_drift_warnings"].append(
            "unexpected state artifacts require review: " + ", ".join(unexpected_state[:5])
        )
    return audit


def evaluate_engagement(
    eng_dir: Path,
    *,
    receipt_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> dict[str, Any]:
    """Run a deterministic heuristic audit over empirical evidence bundles."""
    challenges = load_challenges()
    artifacts = collect_engagement_artifacts(eng_dir)
    proof = evaluate_technical_proof(
        eng_dir,
        challenges,
        receipt_key=receipt_key,
        trusted_fixture=trusted_fixture,
    )
    validated = _validated_blocks(artifacts["hypotheses_text"])
    details: list[dict[str, Any]] = []

    # FIND-confirmed challenges (validated hypothesis + substantive linked
    # finding) count as proven even when the execution bundle was truncated
    # and no longer matches bundle rules. This mirrors score.py's
    # technical_union = evidence_hits ∪ finding_confirmed so the heuristic
    # audit and the headline Technical-Proof Recall cannot disagree.
    finding_confirmed: dict[str, list[str]] = {}
    if artifacts.get("hypotheses_text"):
        parsed_hyp = parse_hypotheses(artifacts["hypotheses_text"])
        parsed_find = parse_findings(eng_dir)
        finding_confirmed = finding_confirmed_challenge_ids(parsed_hyp, parsed_find, challenges)

    for challenge in challenges:
        challenge_id = str(challenge["id"])
        bundles = proof.get(challenge_id, [])
        confirmed_via_finding = finding_confirmed.get(challenge_id, [])
        paths = {
            path.relative_to(eng_dir.resolve()).as_posix()
            for bundle in bundles
            for path in bundle.files
        }
        formalized = any(
            _block_cites_bundle(eng_dir, block, challenge_id, paths) for block in validated
        )
        if bundles or confirmed_via_finding:
            status = "PROVEN"
            if confirmed_via_finding and not paths:
                paths = set(confirmed_via_finding)
        else:
            status = "NOT_PROVEN"
        details.append(
            {
                "id": challenge_id,
                "status": status,
                "formalized": formalized,
                "evidence_paths": sorted(paths),
                "reasoning": (
                    "correlated empirical proof bundle matched endpoint-specific rules"
                    if bundles
                    else (
                        "confirmed via Validated hypothesis + substantive finding file"
                        if confirmed_via_finding
                        else "no decisive request/output proof bundle matched the challenge"
                    )
                ),
            }
        )

    proven = sum(item["status"] == "PROVEN" for item in details)
    formalized = sum(item["status"] == "PROVEN" and item["formalized"] for item in details)
    total = len(challenges)
    findings = (
        [
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted((eng_dir / "evidence" / "findings").glob("FIND-*.md"))
        ]
        if (eng_dir / "evidence" / "findings").exists()
        else []
    )
    broken = broken_evidence_references(eng_dir, [artifacts["hypotheses_text"], *findings])
    return {
        "eng_dir": str(eng_dir),
        "total_challenges": total,
        "proven_count": proven,
        "technical_proof_recall_pct": round(proven / max(total, 1) * 100, 1),
        "formalized_count": formalized,
        "formalization_pct": round(formalized / max(proven, 1) * 100, 1),
        "broken_evidence_references": broken,
        "friction_and_bugs": audit_framework_friction_and_bugs(artifacts),
        "details": details,
    }


if __name__ == "__main__":
    target_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(json.dumps(evaluate_engagement(target_dir), indent=2))
