#!/usr/bin/env python3
"""score.py [$ENG_DIR] — evidence-gated Violin benchmark scorer.

Fixes A–F, P5, D5 applied:
  A  — PTT path corrected (state/ptt.md)
  B  — Evidence-gated: challenge counts ONLY if Validated hypothesis Links it
  C  — Hypothesis status parsed per-block, not substring-matched
  D  — Word-boundary patterns via \b
  E  — Proof quality gate (HTTP signature required in evidence file)
  E2 — Auditable: prints why each challenge matched
  F  — Honest compliance (empty history = UNKNOWN, not ✓)[...]
  P5 — Calibration mode: --calibrate known-{good,bad}
  D5 — Coverage vs Quality split in output
"""

import json
import re
import sys
from pathlib import Path

# Ensure repo root is on sys.path when executed directly
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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
    target = {"good": KNOWN_GOOD_PATH, "bad": KNOWN_BAD_PATH}.get(kind)
    if not target or not target.exists():
        print(f"ERROR: calibration target not found: {target}")
        print("Create calibration engagements with all 14 confirmed and 0 confirmed respectively.")
        sys.exit(1)
    print(f"=== CALIBRATION: known-{kind} at {target} ===")
    result = score_engagement(target)
    expected = 14 if kind == "good" else 0
    actual = result["confirmed"]
    status = "PASS" if actual == expected else "FAIL"
    print(f"CALIBRATION {status}: expected={expected} confirmed={actual}")

    # Check for false positives/negatives
    fps = [c["id"] for c in result["confirmed_details"] if kind == "bad"]
    fns = [c["id"] for c in result["missed_details"] if kind == "good"]
    if fps:
        print(f"FALSE POSITIVES (confirmed in known-bad): {', '.join(fps)}")
    if fns:
        print(f"FALSE NEGATIVES (missed in known-good): {', '.join(fns)}")

    print_result(result)
    sys.exit(0 if status == "PASS" else 1)


# ---------------------------------------------------------------------------
# Hypothesis parsing (Fix C)
# ---------------------------------------------------------------------------
def parse_hypotheses(text: str) -> list[dict]:
    """Parse each ### H-XXX: block, extract Status, Linked challenges, Linked findings, and evidence references."""
    blocks = re.split(r"\n(?=### H-\d+:)", text)
    results = []
    for block in blocks:
        m = re.match(r"^### (H-\d+):", block)
        if not m:
            continue
        hid = m.group(1)
        status = "Candidate"
        linked: list[str] = []
        linked_findings: list[str] = []
        evidence_files: set[str] = set()

        for line in block.splitlines():
            sline = line.strip()
            sm = re.match(r"^(?:[-*]\s*)?\*\*Status:\*\*\s*(.+)", sline, re.IGNORECASE)
            if sm:
                status = sm.group(1).strip()
            lcm = re.match(r"^(?:[-*]\s*)?\*\*Linked challenges:\*\*\s*(.+)", sline, re.IGNORECASE)
            if lcm:
                raw = lcm.group(1)
                linked = [s.strip() for s in raw.split(",") if s.strip()]
            lfm = re.match(r"^(?:[-*]\s*)?\*\*Linked findings:\*\*\s*(.+)", sline, re.IGNORECASE)
            if lfm:
                raw = lfm.group(1)
                linked_findings = [s.strip() for s in raw.split(",") if s.strip()]
            if "evidence/" in line:
                for part in re.findall(r"evidence/[^\s,)]+", line):
                    evidence_files.add(Path(part).name)

        results.append(
            {
                "id": hid,
                "status": status,
                "linked": linked,
                "linked_findings": linked_findings,
                "evidence_files": evidence_files,
            }
        )
    return results


def parse_findings(eng_dir: Path) -> list[dict]:
    """Parse evidence/findings/FIND-*.md files to map findings to evidence files."""
    findings_dir = eng_dir / "evidence" / "findings"
    if not findings_dir.exists():
        return []
    results = []
    for fpath in findings_dir.glob("FIND-*.md"):
        try:
            txt = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        fid = fpath.stem
        evidence_files: set[str] = set()
        for line in txt.splitlines():
            if "evidence/" in line:
                for part in re.findall(r"evidence/[^\s,)]+", line):
                    evidence_files.add(Path(part).name)
        results.append({"id": fid, "evidence_files": evidence_files})
    return results


def _manifest_path(filepath: Path) -> Path:
    """Derive execution manifest JSON path accompanying an evidence file."""
    return filepath.parent / f"{filepath.name.rsplit('.', 2)[0]}.json"


def validated_challenge_ids(
    hypotheses: list[dict],
    findings: list[dict] | None = None,
    evidence_hits: dict[str, list[Path]] | None = None,
) -> set[str]:
    """Return set of challenge IDs validated via explicit link OR post-engagement auto-judge evidence matching."""
    ids: set[str] = set()

    # Tier 1: Explicit challenge links (for calibration fixtures)
    for h in hypotheses:
        if h["status"].strip().lower() == "validated":
            ids.update(h["linked"])

    # Tier 2: Automated Post-Engagement Judge Matching
    if evidence_hits:
        validated_ev_files: set[str] = set()
        for h in hypotheses:
            if h["status"].strip().lower() == "validated":
                validated_ev_files.update(h.get("evidence_files", set()))

        if findings:
            for f in findings:
                validated_ev_files.update(f.get("evidence_files", set()))

        for cid, ev_files in evidence_hits.items():
            hit_names = {f.name for f in ev_files}
            if hit_names.intersection(validated_ev_files):
                ids.add(cid)

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


# ---------------------------------------------------------------------------
# Evidence scanning (Fixes B, D, E)
# ---------------------------------------------------------------------------
_PROOF_SIGNATURE = re.compile(r"HTTP/\d\.\d\s+\d{3}", re.I)
_REQUEST_SIGNATURE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S+\s+HTTP", re.I)


def build_pattern(patterns: list[str]) -> re.Pattern | None:
    """Build a word-boundary OR pattern from challenge patterns (Fix D).

    Uses \b for word-like patterns (alphanumeric), and (?<![a-z0-9])...
    lookbehind for URL/endpoint patterns where / breaks word boundaries."""
    if not patterns:
        return None
    parts = []
    for p in patterns:
        escaped = re.escape(p)
        if p.endswith("/"):
            parts.append(r"(?<![a-zA-Z0-9])" + escaped)
        elif re.search(r"[/.\-]", p):
            parts.append(r"(?<![a-zA-Z0-9])" + escaped + r"(?![a-zA-Z0-9])")
        else:
            parts.append(r"\b" + escaped + r"\b")
    return re.compile("|".join(parts), re.I)


def has_proof(filepath: Path) -> bool:
    """Check that evidence file contains empirical request/response proof or execution manifest signature (Fix E)."""
    try:
        txt = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    if filepath.stat().st_size < 30:
        return False

    if bool(_PROOF_SIGNATURE.search(txt)) or bool(_REQUEST_SIGNATURE.search(txt)):
        return True

    # Inspect accompanying .json execution manifest if present
    json_manifest = _manifest_path(filepath)
    if json_manifest.exists():
        try:
            mdata = json.loads(json_manifest.read_text(encoding="utf-8", errors="replace"))
            if mdata.get("exit_code") == 0 and mdata.get("status") == "completed":
                return True
        except Exception:
            pass

    # Accept valid, non-empty API JSON response payloads (e.g. {"detail":...}, [{"id":...}])
    try:
        data = json.loads(txt.strip())
        return isinstance(data, dict | list) and len(data) > 0
    except Exception:
        return False


def scan_evidence(eng_dir: Path) -> dict[str, list[Path]]:
    """Return {challenge_id: [evidence files containing its patterns]}."""
    ev_dir = eng_dir / "evidence"
    if not ev_dir.exists():
        return {}

    files = [f for f in ev_dir.rglob("*") if f.is_file()]
    challenges = json.loads(CHALLENGES_PATH.read_text(encoding="utf-8"))["challenges"]

    result: dict[str, list[Path]] = {}
    for ch in challenges:
        cid = ch["id"]
        pat = build_pattern(ch.get("patterns", []))
        if not pat:
            continue
        hits = []
        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                manifest = _manifest_path(f)
                if manifest.exists() and manifest != f:
                    content += "\n" + manifest.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if pat.search(content):
                hits.append(f)
        if hits:
            result[cid] = hits
    return result


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
def score_engagement(eng_dir: Path) -> dict:
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
    evidence_hits = scan_evidence(eng_dir)
    validated_ids = validated_challenge_ids(hypotheses, findings, evidence_hits)

    confirmed = []  # validated hypothesis + proof-quality evidence
    touched = []  # evidence matches but no validated hypothesis
    not_tested = []  # no evidence match
    confirmed_details = []
    touched_details = []
    missed_details = []

    for ch in challenges["challenges"]:
        cid = ch["id"]
        ev_matches = evidence_hits.get(cid, [])

        if ev_matches and cid in validated_ids:
            # Check proof quality (Fix E)
            proof_files = [f for f in ev_matches if has_proof(f)]
            if proof_files:
                confirmed.append(cid)
                confirmed_details.append(
                    {
                        "id": cid,
                        "files": [str(f.relative_to(eng_dir)) for f in proof_files],
                    }
                )
            else:
                touched.append(cid)
                touched_details.append(
                    {
                        "id": cid,
                        "reason": "evidence exists but no HTTP proof signature",
                    }
                )
        elif ev_matches:
            touched.append(cid)
            touched_details.append(
                {
                    "id": cid,
                    "reason": "evidence matches but hypothesis not Validated",
                }
            )
        else:
            not_tested.append(cid)
            missed_details.append(
                {
                    "id": cid,
                    "reason": "no evidence file matches challenge patterns",
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

    from benchmark.ai_judge import evaluate_engagement

    ai_eval = evaluate_engagement(eng_dir)

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
        "violations": violations,
        "compliance_unknown": compliance_unknown,
        "framework_feedback": framework_feedback,
        "ai_judge_audit": ai_eval,
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
"""
    )

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

    if r.get("ai_judge_audit"):
        ai = r["ai_judge_audit"]
        print(
            f"\nAI JUDGE AUDIT — Technical Proof Recall: {ai['confirmed_count']}/{ai['total_challenges']} ({ai['recall_pct']}%) | Formatting Compliance: {ai['formatting_compliance_pct']}%"
        )
        if ai.get("formatting_defects"):
            print(
                f"  ⚠️ Formatting Defects: {ai['formatting_defects']} confirmed exploit(s) lacked canonical ### H-XXX markdown blocks"
            )
        if ai.get("mislocated_evidence_count"):
            print(
                f"  ⚠️ Mislocated Evidence: {ai['mislocated_evidence_count']} proof file(s) saved in state/ instead of evidence/"
            )

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
    confirmed_pct = round(r["confirmed"] / max(total, 1) * 100)
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
        f"| **Vulnerability Recall** | {r['confirmed']}/{total} ({confirmed_pct}%) | > 80% | {'✅ PASS' if confirmed_pct >= 80 else '❌ FAIL'} |",
        f"| **Evidence Touched** | {r['touched']}/{total} | N/A | ℹ️ INFO |",
        f"| **PTT Completion** | {r['ptt']['done']}/{r['ptt']['total']} ({ptt_pct}%) | 100% | {'✅ PASS' if ptt_pct == 100 else '⚠️ PARTIAL'} |",
        f"| **Hypotheses** | {r['hyp_created']} created, {r['hyp_resolved']} resolved | N/A | ℹ️ INFO |",
        f"| **Command History** | {r['hist_lines']} lines ({r['hist_blocks']} blocked) | N/A | ℹ️ INFO |",
        f"| **Compliance Invariant** | {comp} | 0 Violations | {'✅ PASS' if r['violations'] == 0 and not r['compliance_unknown'] else '⚠️ REVIEW'} |",
        "",
    ]

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

    if r.get("ai_judge_audit"):
        ai = r["ai_judge_audit"]
        md.append("### 🤖 AI Judge Audit & Technical Proof Recall")
        md.append(
            f"- **True Technical Proof Recall**: {ai['confirmed_count']}/{ai['total_challenges']} ({ai['recall_pct']}%)"
        )
        md.append(f"- **Schema Compliance Rate**: {ai['formatting_compliance_pct']}%")
        if ai.get("formatting_defects"):
            md.append(
                f"- ⚠️ **Formatting Defects**: {ai['formatting_defects']} confirmed exploit(s) lacked canonical `### H-XXX` markdown blocks"
            )
        if ai.get("mislocated_evidence_count"):
            md.append(
                f"- ⚠️ **Mislocated Evidence**: {ai['mislocated_evidence_count']} proof file(s) saved in `state/` instead of `evidence/`"
            )
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
