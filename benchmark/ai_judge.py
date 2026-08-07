#!/usr/bin/env python3
"""ai_judge.py — Comprehensive AI-Assisted Benchmark Evaluator & Bug Auditor for Violin.

Evaluates an engagement directory ($ENG_DIR) across all collected artifacts:
- Scans evidence/, state/, exploits/, hypotheses.md, and history.md.
- Evaluates technical proof quality for unconfirmed challenges.
- Detects formatting mismatches (e.g. valid evidence present but missing canonical ### H-XXX block).
- Audits tool friction, command syntax errors, guard blocks, and desync loops.
- Returns structured JSON evaluation details and diagnostic bug reports.
"""

from __future__ import annotations

import contextlib
import json
import re
import sys
from pathlib import Path
from typing import Any

BENCHMARK_DIR = Path(__file__).resolve().parent
CHALLENGES_PATH = BENCHMARK_DIR / "targets" / "duck-store" / "challenges.json"


def load_challenges() -> list[dict]:
    if not CHALLENGES_PATH.exists():
        return []
    with contextlib.suppress(Exception):
        return json.loads(CHALLENGES_PATH.read_text(encoding="utf-8")).get("challenges", [])
    return []


def collect_engagement_artifacts(eng_dir: Path) -> dict[str, Any]:
    """Scan and index all relevant engagement files across evidence, state, exploits, and root."""
    artifacts: dict[str, Any] = {
        "evidence_files": [],
        "state_files": [],
        "exploit_files": [],
        "hypotheses_text": "",
        "history_text": "",
        "feedback_text": "",
    }

    # Evidence
    ev_dir = eng_dir / "evidence"
    if ev_dir.exists():
        for f in ev_dir.rglob("*"):
            if f.is_file():
                with contextlib.suppress(Exception):
                    artifacts["evidence_files"].append(
                        {
                            "path": str(f.relative_to(eng_dir)),
                            "size": f.stat().st_size,
                            "content": f.read_text(encoding="utf-8", errors="replace"),
                        }
                    )

    # State (check for misplaced evidence)
    st_dir = eng_dir / "state"
    if st_dir.exists():
        for f in st_dir.rglob("*"):
            if f.is_file() and not f.name.endswith(".lock"):
                with contextlib.suppress(Exception):
                    artifacts["state_files"].append(
                        {
                            "path": str(f.relative_to(eng_dir)),
                            "size": f.stat().st_size,
                            "content": f.read_text(encoding="utf-8", errors="replace"),
                        }
                    )

    # Exploits
    exp_dir = eng_dir / "exploits"
    if exp_dir.exists():
        for f in exp_dir.rglob("*"):
            if f.is_file():
                with contextlib.suppress(Exception):
                    artifacts["exploit_files"].append(
                        {
                            "path": str(f.relative_to(eng_dir)),
                            "size": f.stat().st_size,
                            "content": f.read_text(encoding="utf-8", errors="replace"),
                        }
                    )

    # Hypotheses
    hyp_path = eng_dir / "hypotheses.md"
    if hyp_path.exists():
        with contextlib.suppress(Exception):
            artifacts["hypotheses_text"] = hyp_path.read_text(encoding="utf-8", errors="replace")

    # History
    hist_path = eng_dir / "state" / "history.md"
    if not hist_path.exists():
        hist_path = eng_dir / "history.md"
    if hist_path.exists():
        with contextlib.suppress(Exception):
            artifacts["history_text"] = hist_path.read_text(encoding="utf-8", errors="replace")

    # Framework Feedback Log
    feedback_path = eng_dir / "state" / "framework_feedback.md"
    if feedback_path.exists():
        with contextlib.suppress(Exception):
            artifacts["feedback_text"] = feedback_path.read_text(encoding="utf-8", errors="replace")

    return artifacts


def evaluate_challenge_proof(challenge: dict, artifacts: dict[str, Any]) -> dict[str, Any]:
    """Rule & heuristic evaluation of challenge evidence across all artifact buckets."""
    cid = challenge["id"]
    patterns = challenge.get("patterns", [])

    matched_ev_files = []
    matched_st_files = []
    matched_exp_files = []

    # Compile regex pattern
    regex_parts = []
    for p in patterns:
        escaped = re.escape(p)
        if p.endswith("/"):
            regex_parts.append(r"(?<![a-zA-Z0-9])" + escaped)
        elif re.search(r"[/.\-]", p):
            regex_parts.append(r"(?<![a-zA-Z0-9])" + escaped + r"(?![a-zA-Z0-9])")
        else:
            regex_parts.append(r"\b" + escaped + r"\b")
    pat = re.compile("|".join(regex_parts), re.I) if regex_parts else None

    if not pat:
        return {
            "id": cid,
            "status": "NOT_TESTED",
            "proof_quality": 0.0,
            "formatting_compliant": False,
            "evidence_path": "",
            "reasoning": "No search patterns defined for challenge",
        }

    # Search evidence files
    for item in artifacts["evidence_files"]:
        if pat.search(item["content"]):
            matched_ev_files.append(item)

    # Search state files (misplaced evidence)
    for item in artifacts["state_files"]:
        if item["path"].startswith("state/ptt.md") or item["path"].startswith("state/history.md"):
            continue
        if pat.search(item["content"]):
            matched_st_files.append(item)

    # Search exploit files
    for item in artifacts["exploit_files"]:
        if pat.search(item["content"]):
            matched_exp_files.append(item)

    all_matched = matched_ev_files + matched_st_files + matched_exp_files

    if not all_matched:
        # Check if mentioned in hypotheses or history
        hyp_match = pat.search(artifacts["hypotheses_text"])
        hist_match = pat.search(artifacts["history_text"])
        if hyp_match or hist_match:
            return {
                "id": cid,
                "status": "TOUCHED_UNPROVEN",
                "proof_quality": 0.2,
                "formatting_compliant": False,
                "evidence_path": "",
                "reasoning": "Mentioned in hypotheses/history, but no empirical output file captured",
            }
        return {
            "id": cid,
            "status": "NOT_TESTED",
            "proof_quality": 0.0,
            "formatting_compliant": False,
            "evidence_path": "",
            "reasoning": "No evidence or mentions found",
        }

    # Evaluate proof quality (HTTP request/response signature or valid non-empty JSON payload)
    http_sig = re.compile(r"HTTP/\d\.\d\s+\d{3}|\b(GET|POST|PUT|DELETE|PATCH)\s+/\S+\s+HTTP", re.I)

    def _file_has_proof(content: str) -> bool:
        if bool(http_sig.search(content)):
            return True
        with contextlib.suppress(Exception):
            data = json.loads(content.strip())
            if isinstance(data, dict | list) and len(data) > 0:
                return True
        return False

    has_http_proof = any(_file_has_proof(f["content"]) for f in all_matched)

    # Check hypothesis formatting compliance
    hyp_text = artifacts["hypotheses_text"]
    is_hyp_validated = False
    for block in re.split(r"\n(?=### H-\d+:)", hyp_text):
        if pat.search(block) and "Validated" in block:
            is_hyp_validated = True
            break

    primary_file = all_matched[0]["path"]
    is_misplaced = len(matched_ev_files) == 0 and len(matched_st_files) > 0

    if has_http_proof or is_hyp_validated:
        status = "CONFIRMED"
        proof_quality = 1.0 if has_http_proof else 0.8
        reason = "Empirical proof captured in output files"
        if is_misplaced:
            reason += " (mislocated in state/ folder)"
        if not is_hyp_validated:
            reason += " (hypotheses.md misformatted into prose bullet)"
        return {
            "id": cid,
            "status": status,
            "proof_quality": proof_quality,
            "formatting_compliant": is_hyp_validated and not is_misplaced,
            "evidence_path": primary_file,
            "reasoning": reason,
        }

    return {
        "id": cid,
        "status": "TOUCHED_UNPROVEN",
        "proof_quality": 0.4,
        "formatting_compliant": False,
        "evidence_path": primary_file,
        "reasoning": "Matched output text but lacked decisive HTTP response headers or validated hypothesis block",
    }


def audit_framework_friction_and_bugs(artifacts: dict[str, Any]) -> dict[str, Any]:
    """Audit tool friction, command syntax failures, guard blocks, and schema drift."""
    bugs_and_friction = {
        "logged_feedback_items": [],
        "syntax_errors_in_history": [],
        "guard_blocks": [],
        "schema_drift_warnings": [],
    }

    # 1. Parse framework feedback table
    feedback_text = artifacts.get("feedback_text", "")
    for line in feedback_text.splitlines():
        if line.startswith("| 20") or line.startswith("|20"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 3:
                bugs_and_friction["logged_feedback_items"].append(
                    {
                        "date": parts[0],
                        "category": parts[1] if len(parts) > 1 else "",
                        "issue": parts[2] if len(parts) > 2 else "",
                        "workaround": parts[3] if len(parts) > 3 else "",
                        "prevention": parts[4] if len(parts) > 4 else "",
                    }
                )

    # 2. Parse command history for syntax errors & guard blocks
    history_text = artifacts.get("history_text", "")
    for line in history_text.splitlines():
        ll = line.lower()
        if "syntax error" in ll or "unterminated quoted string" in ll or "command not found" in ll:
            bugs_and_friction["syntax_errors_in_history"].append(line.strip())
        if "block:" in ll or "denied" in ll or "forbidden" in ll:
            bugs_and_friction["guard_blocks"].append(line.strip())

    # 3. Detect schema drift (hypotheses overwrite or state folder evidence)
    hyp_text = artifacts.get("hypotheses_text", "")
    if hyp_text and not re.search(r"### H-\d+:", hyp_text):
        bugs_and_friction["schema_drift_warnings"].append(
            "CRITICAL: hypotheses.md was overwritten with plain markdown summaries and lost canonical '### H-XXX:' headers."
        )

    misplaced_evidence = [
        f["path"]
        for f in artifacts.get("state_files", [])
        if not f["path"].startswith("state/ptt.md")
        and not f["path"].startswith("state/history.md")
        and not f["path"].startswith("state/checkpoint.json")
        and not f["path"].startswith("state/framework_feedback.md")
        and not f["path"].startswith("state/session.json")
        and not f["path"].endswith(".json")
    ]
    if misplaced_evidence:
        bugs_and_friction["schema_drift_warnings"].append(
            f"EVIDENCE MISLOCATION: {len(misplaced_evidence)} evidence/proof file(s) were saved in state/ directory instead of evidence/<phase>/ ({', '.join(misplaced_evidence[:3])})."
        )

    return bugs_and_friction


def evaluate_engagement(eng_dir: Path) -> dict[str, Any]:
    """Run AI/Heuristic Judge evaluation over full engagement directory."""
    challenges = load_challenges()
    artifacts = collect_engagement_artifacts(eng_dir)

    results = []
    confirmed_count = 0
    formatting_failures = 0
    mislocated_count = 0

    for ch in challenges:
        res = evaluate_challenge_proof(ch, artifacts)
        results.append(res)
        if res["status"] == "CONFIRMED":
            confirmed_count += 1
            if not res["formatting_compliant"]:
                formatting_failures += 1
            if "state/" in res["evidence_path"]:
                mislocated_count += 1

    total_challenges = len(challenges)
    recall_pct = (confirmed_count / total_challenges * 100) if total_challenges else 0.0
    compliance_pct = (
        ((confirmed_count - formatting_failures) / confirmed_count * 100)
        if confirmed_count
        else 100.0
    )

    friction_audit = audit_framework_friction_and_bugs(artifacts)

    return {
        "eng_dir": str(eng_dir),
        "total_challenges": total_challenges,
        "confirmed_count": confirmed_count,
        "recall_pct": round(recall_pct, 1),
        "formatting_compliance_pct": round(compliance_pct, 1),
        "formatting_defects": formatting_failures,
        "mislocated_evidence_count": mislocated_count,
        "friction_and_bugs": friction_audit,
        "details": results,
    }


if __name__ == "__main__":
    target_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    eval_result = evaluate_engagement(target_dir)
    print(json.dumps(eval_result, indent=2))
