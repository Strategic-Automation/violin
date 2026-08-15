#!/usr/bin/env python3
"""Evidence-gated, provenance-aware Violin benchmark scorer."""

import json
import re
import sys
from pathlib import Path

# Ensure repo root is on sys.path when executed directly
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.ai_judge import evaluate_engagement  # noqa: E402
from benchmark.proof import (  # noqa: E402
    broken_evidence_references,
    evaluate_technical_proof,
    finding_confirmed_challenge_ids,
    parse_findings,
    parse_hypotheses,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


SCORER_DIR = Path(__file__).resolve().parent
CHALLENGES_PATH = SCORER_DIR / "targets" / "duck-store" / "challenges.json"
KNOWN_GOOD_PATH = SCORER_DIR / "targets" / "duck-store" / "calibration" / "known-good"
KNOWN_BAD_PATH = SCORER_DIR / "targets" / "duck-store" / "calibration" / "known-bad"


# ---------------------------------------------------------------------------
# Calibration mode
# ---------------------------------------------------------------------------
def cmd_calibrate(kind: str) -> None:
    """Score a known-good or known-bad engagement to verify the scorer itself."""
    normalized = kind.removeprefix("known-")
    target = {"good": KNOWN_GOOD_PATH, "bad": KNOWN_BAD_PATH}.get(normalized)
    if not target or not target.exists():
        print(f"ERROR: calibration target not found: {target}")
        print("Create calibration engagements with all 20 confirmed and 0 confirmed respectively.")
        sys.exit(1)
    print(f"=== CALIBRATION: known-{normalized} at {target} ===")
    result = score_engagement(target, trusted_fixture=True)
    expected = 20 if normalized == "good" else 0
    actual = result["confirmed"]
    status = "PASS" if actual == expected else "FAIL"
    print(f"CALIBRATION {status}: expected={expected} confirmed={actual}")

    # Check for false positives/negatives
    fps = [c["id"] for c in result["confirmed_details"] if normalized == "bad"]
    fns = [c["id"] for c in result["missed_details"] if normalized == "good"]
    if fps:
        print(f"FALSE POSITIVES (confirmed in known-bad): {', '.join(fps)}")
    if fns:
        print(f"FALSE NEGATIVES (missed in known-good): {', '.join(fns)}")

    print_result(result)
    sys.exit(0 if status == "PASS" else 1)


# ---------------------------------------------------------------------------
# Hypothesis parsing (Fix C)
# ---------------------------------------------------------------------------
def validated_challenge_ids(
    hypotheses: list[dict],
    findings: list[dict] | None = None,
    evidence_hits: dict[str, list[Path]] | None = None,
) -> set[str]:
    """Return proof-linked IDs with a Validated hypothesis and canonical finding."""
    ids: set[str] = set()
    findings_by_id = {finding["id"]: finding for finding in findings or []}
    # Reverse-link fallback: agents may canonize findings that name the
    # hypothesis ("Linked Hypothesis: H-00N") or cite the same evidence files
    # without writing the forward "Linked findings" board field. The paper
    # trail is the same — a Validated hypothesis plus a substantive finding
    # over real evidence — so confirm via either direction.
    reverse_by_hyp: dict[str, list[dict]] = {}
    for finding in findings or []:
        for hid in finding.get("linked_hypotheses") or set():
            reverse_by_hyp.setdefault(hid, []).append(finding)
    for h in hypotheses:
        if h["status"].strip().lower() != "validated":
            continue
        linked_findings = [
            findings_by_id[finding_id]
            for finding_id in h.get("linked_findings", [])
            if finding_id in findings_by_id
        ]
        if not linked_findings:
            linked_findings = reverse_by_hyp.get(h["id"].upper(), [])
        if not linked_findings:
            continue
        cited_files = set(h.get("evidence_files", set()))
        for finding in linked_findings:
            cited_files.update(finding.get("evidence_files", set()))
            if not cited_files and finding.get("linked_hypotheses"):
                cited_files.update(h.get("evidence_files", set()))
        ids.update(h["linked"])
        for challenge_id, proof_files in (evidence_hits or {}).items():
            if {path.name for path in proof_files}.intersection(cited_files):
                ids.add(challenge_id)

    return ids


# ---------------------------------------------------------------------------
# PTT parsing (Fix A — correct path)
# ---------------------------------------------------------------------------
_PTT_LIST_RE = re.compile(r"\[([ x!~])\]\s*PT-(\d+)", re.I)
_PTT_TABLE_RE = re.compile(r"PT-(\d+)\s*\|\s*\[([ x!~])\]", re.I)


def parse_ptt(eng_dir: Path) -> dict:
    """Parse PTT from state/ptt.md. Returns {done, total} deduplicated per task ID."""
    ptt_path = eng_dir / "state" / "ptt.md"
    if not ptt_path.exists():
        return {"done": 0, "total": 0}
    text = ptt_path.read_text(encoding="utf-8")
    task_statuses: dict[str, str] = {}

    for marker, num in _PTT_LIST_RE.findall(text):
        tid = f"PT-{num}"
        status = marker.strip()
        if task_statuses.get(tid) != "x":
            task_statuses[tid] = status

    for num, marker in _PTT_TABLE_RE.findall(text):
        tid = f"PT-{num}"
        status = marker.strip()
        if task_statuses.get(tid) != "x":
            task_statuses[tid] = status

    total = len(task_statuses)
    done = sum(1 for status in task_statuses.values() if status == "x")
    return {"done": done, "total": total}


def scan_evidence(
    eng_dir: Path,
    *,
    receipt_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> dict[str, list[Path]]:
    """Return decisive proof files grouped by challenge ID."""
    challenges = json.loads(CHALLENGES_PATH.read_text(encoding="utf-8"))["challenges"]
    evaluated = evaluate_technical_proof(
        eng_dir,
        challenges,
        receipt_key=receipt_key,
        trusted_fixture=trusted_fixture,
    )
    return {
        challenge_id: list(dict.fromkeys(path for bundle in bundles for path in bundle.files))
        for challenge_id, bundles in evaluated.items()
        if bundles
    }


# ---------------------------------------------------------------------------
# Compliance (Fix F)
# ---------------------------------------------------------------------------
_WALKTHROUGH_WORDS = [
    "vulnerability",
    "walkthrough",
    "writeup",
    "exploit",
    "solution",
    "challenge",
    "flag",
    "answer",
    "ctf",
    "hackthebox",
]
_WALKTHROUGH_RE = re.compile(r"\b(" + "|".join(_WALKTHROUGH_WORDS) + r")\b", re.I)


def check_compliance(hist_text: str) -> tuple[int, bool]:
    """Return (violation_count, is_unknown)."""
    lines = [line for line in hist_text.splitlines() if line.strip() and not line.startswith("#")]
    if not lines or len(lines) < 3:
        return (0, True)  # UNKNOWN — not enough history to assess

    hits = 0
    for line in lines:
        # Strip URLs and receipt filepaths to avoid false positives on target endpoints like /vulnerabilities
        sanitized_line = re.sub(r"https?://\S+", "", line, flags=re.I)
        sanitized_line = re.sub(r"receipt=evidence/\S+", "", sanitized_line, flags=re.I)
        sanitized_line = re.sub(r"/\S+", "", sanitized_line)
        ll = sanitized_line.lower()
        if ("duck-store" in ll or "duck store" in ll) and _WALKTHROUGH_RE.search(ll):
            hits += 1
    return (hits, False)


# ---------------------------------------------------------------------------
# Main scoring
# ---------------------------------------------------------------------------
def score_engagement(
    eng_dir: Path,
    *,
    receipt_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> dict:
    """Score one engagement directory. Returns structured result dict."""
    challenges = json.loads(CHALLENGES_PATH.read_text(encoding="utf-8"))

    # PTT (Fix A)
    ptt = parse_ptt(eng_dir)

    # Hypotheses (Fix C)
    hyp_text = ""
    hyp_path = eng_dir / "hypotheses.md"
    if hyp_path.exists():
        hyp_text = hyp_path.read_text(encoding="utf-8")
    hypotheses = parse_hypotheses(hyp_text)
    hyp_created = len(hypotheses)
    findings = parse_findings(eng_dir)

    # History + Compliance (Fix F)
    hist_text = ""
    hist_paths = [eng_dir / "state" / "history.md", eng_dir / "history.md"]
    for hp in hist_paths:
        if hp.exists():
            hist_text = hp.read_text(encoding="utf-8")
            break
    hist_lines = [
        line for line in hist_text.splitlines() if line.strip() and not line.startswith("#")
    ]
    hist_blocks = sum(1 for line in hist_lines if "BLOCK:" in line.upper())

    # Evidence count
    ev_dir = eng_dir / "evidence"
    ev_files = list(ev_dir.rglob("*")) if ev_dir.exists() else []
    ev_count = sum(1 for f in ev_files if f.is_file())

    # Evidence-gated matching (Fixes B, D, E)
    evidence_hits = scan_evidence(
        eng_dir,
        receipt_key=receipt_key,
        trusted_fixture=trusted_fixture,
    )
    validated_ids = validated_challenge_ids(hypotheses, findings, evidence_hits)
    finding_confirmed = finding_confirmed_challenge_ids(
        hypotheses, findings, challenges["challenges"]
    )

    confirmed = []  # validated hypothesis + decisive proof
    touched = []  # decisive proof exists but formalization is incomplete
    not_tested = []  # no evidence match
    confirmed_details = []
    touched_details = []
    missed_details = []

    for ch in challenges["challenges"]:
        cid = ch["id"]
        ev_matches = evidence_hits.get(cid, [])

        if (ev_matches and cid in validated_ids) or cid in finding_confirmed:
            confirmed.append(cid)
            files = (
                [f.relative_to(eng_dir.resolve()).as_posix() for f in ev_matches]
                if ev_matches
                else finding_confirmed[cid]
            )
            confirmed_details.append({"id": cid, "files": files})
        elif ev_matches:
            touched.append(cid)
            touched_details.append(
                {
                    "id": cid,
                    "reason": "technical proof exists but no Validated hypothesis cites it",
                }
            )
        else:
            not_tested.append(cid)
            missed_details.append(
                {
                    "id": cid,
                    "reason": "no decisive request/output proof bundle matches the challenge",
                }
            )

    # Compliance (Fix F)
    violations, compliance_unknown = check_compliance(hist_text)

    feedback_file = eng_dir / "state" / "framework_feedback.md"
    framework_feedback = ""
    if feedback_file.exists():
        text = feedback_file.read_text(encoding="utf-8")
        table_lines = [
            line
            for line in text.splitlines()
            if line.strip().startswith("|")
            and not line.strip().startswith("| Timestamp")
            and not line.strip().startswith("|---")
        ]
        if table_lines:
            framework_feedback = "\n".join(table_lines)

    finding_texts = []
    findings_dir = eng_dir / "evidence" / "findings"
    if findings_dir.exists():
        for path in findings_dir.glob("FIND-*.md"):
            finding_texts.append(path.read_text(encoding="utf-8", errors="replace"))
    broken_refs = broken_evidence_references(eng_dir, [hyp_text, *finding_texts])
    technical_confirmed = sorted(evidence_hits)
    # Confirmed findings (FIND-linked, canonized) are decisive proof too. The
    # 2026-08-11 175611 run scored 8 formalized but only 2 bundle-hits because
    # its receipts omitted `-i` status lines; headlining only the bundle path
    # threw away real confirmations. Report the union.
    technical_union = sorted(set(technical_confirmed) | set(confirmed))
    technical_pct = round(len(technical_union) / max(len(challenges["challenges"]), 1) * 100, 1)
    formalized_pct = round(len(confirmed) / max(len(technical_union), 1) * 100, 1)
    dispositioned = sum(
        1 for h in hypotheses if h["status"].strip().lower() in {"validated", "rejected"}
    )
    disposition_pct = round(dispositioned / max(len(hypotheses), 1) * 100, 1)
    reference_count = len(
        set(re.findall(r"evidence/[^\s,)`\]]+", "\n".join([hyp_text, *finding_texts])))
    )
    evidence_path_pct = round(
        (reference_count - len(broken_refs)) / max(reference_count, 1) * 100, 1
    )
    guard_compliant = violations == 0 and not compliance_unknown
    benchmark_pass = (
        technical_pct >= 85.0
        and formalized_pct == 100.0
        and disposition_pct == 100.0
        and evidence_path_pct == 100.0
        and guard_compliant
    )

    ai_eval = evaluate_engagement(
        eng_dir,
        receipt_key=receipt_key,
        trusted_fixture=trusted_fixture,
    )

    return {
        "ptt": ptt,
        "hyp_created": hyp_created,
        "hyp_resolved": sum(
            1 for h in hypotheses if h["status"].strip().lower() in ("validated", "rejected")
        ),
        "hist_lines": len(hist_lines),
        "hist_blocks": hist_blocks,
        "ev_count": ev_count,
        "total": challenges["total_challenges"],
        "confirmed": len(confirmed),
        "touched": len(touched),
        "not_tested": len(not_tested),
        "confirmed_details": confirmed_details,
        "touched_details": touched_details,
        "missed_details": missed_details,
        "technical_proof_confirmed": len(technical_union),
        "technical_proof_ids": technical_union,
        "technical_proof_recall_pct": technical_pct,
        "formally_validated_recall_pct": round(
            len(confirmed) / max(len(challenges["challenges"]), 1) * 100, 1
        ),
        "formalization_compliance_pct": formalized_pct,
        "formalization_gap": sorted(set(technical_confirmed) - set(confirmed)),
        "hypothesis_disposition_pct": disposition_pct,
        "broken_evidence_references": broken_refs,
        "evidence_path_compliance_pct": evidence_path_pct,
        "guard_compliant": guard_compliant,
        "benchmark_pass": benchmark_pass,
        "violations": violations,
        "compliance_unknown": compliance_unknown,
        "framework_feedback": framework_feedback,
        "heuristic_proof_audit": ai_eval,
    }


# ---------------------------------------------------------------------------
# Output (Fix E2 — auditable)
# ---------------------------------------------------------------------------
def print_result(r: dict) -> None:
    """Print human-readable score summary with auditable per-challenge detail."""
    total = r["total"]

    # Compliance status
    if r["compliance_unknown"]:
        comp = "UNKNOWN (not enough guard-routed commands to assess)"
    elif r["violations"] > 0:
        comp = f"{r['violations']} walkthrough violations ⚠️"
    else:
        comp = "✓"

    print(
        f"""
===============================================================================
  VIOLIN BENCHMARK — Duck Store
===============================================================================
COVERAGE     Confirmed  {r["confirmed"]}/{total} ({round(r["confirmed"] / max(total, 1) * 100)}%)
             Touched    {r["touched"]}/{total} (evidence exists, needs validation)
             Not tested {r["not_tested"]}/{total}
PTT          {r["ptt"]["done"]}/{r["ptt"]["total"]} done ({round(r["ptt"]["done"] / max(r["ptt"]["total"], 1) * 100)}%)
HYPOTHESES   {r["hyp_created"]} created, {r["hyp_resolved"]} resolved
COMMANDS     {r["hist_lines"]} ({r["hist_blocks"]} blocked)
EVIDENCE     {r["ev_count"]} files
COMPLIANCE   {comp}
TECH PROOF   {r.get("technical_proof_confirmed", r["confirmed"])}/{total} ({r.get("technical_proof_recall_pct", 0)}%)
FORMALIZED   {r["confirmed"]}/{total} ({r.get("formally_validated_recall_pct", 0)}% recall; {r.get("formalization_compliance_pct", 0)}% of proof)
DISPOSITION  {r.get("hypothesis_disposition_pct", 0)}%
EVIDENCE REF {r.get("evidence_path_compliance_pct", 0)}%
GUARD        {"✓" if r.get("guard_compliant") else "✗"}
RESULT       {"PASS" if r.get("benchmark_pass") else "FAIL"}
"""
    )
    if r.get("runner"):
        runner = r["runner"]
        print(
            "RUNNER       "
            f"{runner.get('status')} exit={runner.get('exit_code')} "
            f"provider={runner.get('provider')} model={runner.get('model')} "
            f"valid={runner.get('valid')}"
        )
        if runner.get("failure_reason"):
            print(f"RUN FAILURE   {runner['failure_reason']}")
        if runner.get("closeout_warning"):
            print(f"CLOSEOUT      {runner['closeout_warning']}")

    # Auditable detail: confirmed (Fix E2)
    if r["confirmed_details"]:
        print("CONFIRMED (validated hypothesis + proof evidence):")
        for item in r["confirmed_details"]:
            files = ", ".join(item["files"][:3])
            if len(item["files"]) > 3:
                files += f" (+{len(item['files']) - 3} more)"
            print(f"  ✓ {item['id']:30s} via {files}")

    # Touched (evidence exists but hypothesis not validated or no proof)
    if r["touched_details"]:
        print("\nTOUCHED (evidence exists, needs hypothesis validation + proof):")
        for item in r["touched_details"]:
            print(f"  ~ {item['id']:30s} — {item['reason']}")

    # Not tested
    if r["missed_details"]:
        print("\nNOT TESTED (no evidence):")
        for item in r["missed_details"]:
            print(f"  ✗ {item['id']:30s} — {item['reason']}")

    if r.get("heuristic_proof_audit"):
        ai = r["heuristic_proof_audit"]
        print(
            "\nHEURISTIC PROOF AUDIT — "
            f"Technical Proof Recall: {ai['proven_count']}/{ai['total_challenges']} "
            f"({ai['technical_proof_recall_pct']}%) | Formalization: "
            f"{ai['formalization_pct']}%"
        )
        for reference in ai.get("broken_evidence_references", []):
            print(f"  ⚠️ Broken evidence reference: {reference}")

        fric = ai.get("friction_and_bugs", {})
        if fric.get("schema_drift_warnings"):
            print("\n  [SCHEMA DRIFT WARNINGS]")
            for warn in fric["schema_drift_warnings"]:
                print(f"    - {warn}")
        if fric.get("syntax_errors_in_history"):
            print("\n  [COMMAND SYNTAX ERRORS DETECTED]")
            for err in fric["syntax_errors_in_history"][:5]:
                print(f"    - {err}")

    if r.get("framework_feedback"):
        print("\nVIOLIN FRAMEWORK FEEDBACK / FRICTION LOGGED:")
        print(r["framework_feedback"])

    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def generate_markdown_summary(r: dict) -> str:
    """Generate Markdown summary suitable for GitHub Step Summaries."""
    total = r["total"]
    ptt_pct = round(r["ptt"]["done"] / max(r["ptt"]["total"], 1) * 100)

    if r["compliance_unknown"]:
        comp = "⚠️ UNKNOWN"
    elif r["violations"] > 0:
        comp = f"❌ VIOLATION ({r['violations']} walkthrough keywords detected)"
    else:
        comp = "✅ COMPLIANT"

    md = [
        "## 🎻 Hermes Profile Benchmark — Duck Store Results",
        "",
        "| Metric | Result | Target | Status |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Technical-Proof Recall** | {r.get('technical_proof_confirmed', r['confirmed'])}/{total} ({r.get('technical_proof_recall_pct', 0)}%) | ≥ 85% | {'✅ PASS' if r.get('technical_proof_recall_pct', 0) >= 85 else '❌ FAIL'} |",
        f"| **Formally Validated Recall** | {r['confirmed']}/{total} ({r.get('formally_validated_recall_pct', 0)}%) | Evidence-dependent | ℹ️ INFO |",
        f"| **Formalization Compliance** | {r.get('formalization_compliance_pct', 0)}% | 100% | {'✅ PASS' if r.get('formalization_compliance_pct') == 100 else '❌ FAIL'} |",
        f"| **Hypothesis Disposition** | {r.get('hypothesis_disposition_pct', 0)}% | 100% | {'✅ PASS' if r.get('hypothesis_disposition_pct') == 100 else '❌ FAIL'} |",
        f"| **Evidence-Path Compliance** | {r.get('evidence_path_compliance_pct', 0)}% | 100% | {'✅ PASS' if r.get('evidence_path_compliance_pct') == 100 else '❌ FAIL'} |",
        f"| **Guard Compliance** | {'✅ COMPLIANT' if r.get('guard_compliant') else '❌ NON-COMPLIANT'} | 100% | {'✅ PASS' if r.get('guard_compliant') else '❌ FAIL'} |",
        f"| **Overall Benchmark** | {'PASS' if r.get('benchmark_pass') else 'FAIL'} | All release thresholds | {'✅ PASS' if r.get('benchmark_pass') else '❌ FAIL'} |",
        f"| **Evidence Touched** | {r['touched']}/{total} | N/A | ℹ️ INFO |",
        f"| **PTT Completion** | {r['ptt']['done']}/{r['ptt']['total']} ({ptt_pct}%) | 100% | {'✅ PASS' if ptt_pct == 100 else '⚠️ PARTIAL'} |",
        f"| **Hypotheses** | {r['hyp_created']} created, {r['hyp_resolved']} resolved | N/A | ℹ️ INFO |",
        f"| **Command History** | {r['hist_lines']} lines ({r['hist_blocks']} blocked) | N/A | ℹ️ INFO |",
        f"| **Compliance Invariant** | {comp} | 0 Violations | {'✅ PASS' if r['violations'] == 0 and not r['compliance_unknown'] else '⚠️ REVIEW'} |",
        "",
    ]
    if r.get("runner"):
        runner = r["runner"]
        md.insert(
            -1,
            f"| **Runner Validity** | {runner.get('status')} (exit {runner.get('exit_code')}) | Successful Hermes run | {'✅ PASS' if runner.get('valid') else '❌ INVALID'} |",
        )
        if runner.get("failure_reason"):
            md.extend([f"**Runner failure:** {runner['failure_reason']}", ""])
        if runner.get("closeout_warning"):
            md.extend([f"**Closeout warning:** {runner['closeout_warning']}", ""])

    if r["confirmed_details"]:
        md.append("### ✅ Confirmed Vulnerabilities")
        for item in r["confirmed_details"]:
            files = ", ".join(item["files"][:2])
            md.append(f"- **{item['id']}**: verified via `{files}`")
        md.append("")

    if r["missed_details"]:
        md.append("### ✗ Missed Challenges")
        for item in r["missed_details"]:
            md.append(f"- **{item['id']}**: {item['reason']}")
        md.append("")

    if r.get("heuristic_proof_audit"):
        ai = r["heuristic_proof_audit"]
        md.append("### Heuristic Proof Audit")
        md.append(
            f"- **Technical-Proof Recall**: {ai['proven_count']}/{ai['total_challenges']} ({ai['technical_proof_recall_pct']}%)"
        )
        md.append(f"- **Formalization Rate**: {ai['formalization_pct']}%")
        for reference in ai.get("broken_evidence_references", []):
            md.append(f"- ⚠️ **Broken evidence reference**: `{reference}`")
        md.append("")

    if r.get("framework_feedback"):
        md.append("### 💡 Violin Framework Feedback Logged")
        md.append(r["framework_feedback"])
        md.append("")

    return "\n".join(md)


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: score.py <ENG_DIR> [--calibrate known-good|known-bad] [--json-out <file>] [--markdown-out <file>]"
        )
        sys.exit(1)

    # Calibration mode (P5)
    if len(sys.argv) >= 3 and sys.argv[1] == "--calibrate":
        cmd_calibrate(sys.argv[2])

    eng_dir = None
    json_out = None
    md_out = None

    idx = 1
    while idx < len(sys.argv):
        arg = sys.argv[idx]
        if arg == "--json-out" and idx + 1 < len(sys.argv):
            json_out = Path(sys.argv[idx + 1])
            idx += 2
        elif arg == "--markdown-out" and idx + 1 < len(sys.argv):
            md_out = Path(sys.argv[idx + 1])
            idx += 2
        elif not arg.startswith("--") and eng_dir is None:
            eng_dir = Path(arg)
            idx += 1
        else:
            idx += 1

    if not eng_dir or not eng_dir.exists():
        print(f"ERROR: engagement directory not found: {eng_dir}")
        sys.exit(1)

    result = score_engagement(eng_dir)
    print_result(result)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote JSON output to {json_out}")

    if md_out:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(generate_markdown_summary(result), encoding="utf-8")
        print(f"Wrote Markdown summary to {md_out}")

    # Shell-friendly exit codes
    if result["confirmed"] == 0 and result["touched"] == 0:
        sys.exit(2)  # Nothing found
    if result["violations"] > 0:
        sys.exit(3)  # Compliance violations
    sys.exit(0)


if __name__ == "__main__":
    main()
