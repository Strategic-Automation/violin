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
    """Parse each ### H-XXX: block, extract Status and Linked challenges."""
    blocks = re.split(r"\n(?=### H-\d+:)", text)
    results = []
    for block in blocks:
        m = re.match(r"^### (H-\d+):", block)
        if not m:
            continue
        hid = m.group(1)
        status = "Candidate"
        linked: list[str] = []
        for line in block.splitlines():
            if re.match(r"^\*\*Status:\*\*\s*(.+)", line.strip()):
                status = re.match(r"^\*\*Status:\*\*\s*(.+)", line.strip()).group(1).strip()
            if re.match(r"^\*\*Linked challenges:\*\*\s*(.+)", line.strip()):
                raw = re.match(r"^\*\*Linked challenges:\*\*\s*(.+)", line.strip()).group(1)
                linked = [s.strip() for s in raw.split(",") if s.strip()]
        results.append({"id": hid, "status": status, "linked": linked})
    return results


def validated_challenge_ids(hypotheses: list[dict]) -> set[str]:
    """Return set of challenge IDs explicitly Validated in hypotheses."""
    ids: set[str] = set()
    for h in hypotheses:
        if h["status"].strip().lower() == "validated":
            ids.update(h["linked"])
    return ids


# ---------------------------------------------------------------------------
# PTT parsing (Fix A — correct path)
# ---------------------------------------------------------------------------
_PTT_RE = re.compile(r"\[([ x!~])\].*?PT-(\d+)")


def parse_ptt(eng_dir: Path) -> dict:
    """Parse PTT from state/ptt.md (Fix A). Returns {done, total}."""
    ptt_path = eng_dir / "state" / "ptt.md"
    if not ptt_path.exists():
        return {"done": 0, "total": 0}
    text = ptt_path.read_text()
    rows = _PTT_RE.findall(text)
    total = len(rows)
    done = sum(1 for marker, _ in rows if marker.strip() == "x")
    return {"done": done, "total": total}


# ---------------------------------------------------------------------------
# Evidence scanning (Fixes B, D, E)
# ---------------------------------------------------------------------------
_PROOF_SIGNATURE = re.compile(r"HTTP/\d\.\d\s+\d{3}", re.I)
_REQUEST_SIGNATURE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S+\s+HTTP", re.I
)


def build_pattern(challenge_id: str, patterns: list[str]) -> re.Pattern | None:
    """Build a word-boundary OR pattern from challenge patterns (Fix D).

    Uses \b for word-like patterns (alphanumeric), and (?<![a-z0-9])...
    lookbehind for URL/endpoint patterns where / breaks word boundaries."""
    if not patterns:
        return None
    parts = []
    for p in patterns:
        escaped = re.escape(p)
        # URL-like patterns (contain /, ., -) need non-word-boundary matching
        if re.search(r'[/.\-]', p):
            parts.append(r"(?<![a-zA-Z0-9])" + escaped + r"(?![a-zA-Z0-9])")
        else:
            parts.append(r"\b" + escaped + r"\b")
    return re.compile("|".join(parts), re.I)


def has_proof(filepath: Path) -> bool:
    """Check that evidence file contains HTTP request/response (Fix E)."""
    try:
        txt = filepath.read_text(errors="replace")
    except Exception:
        return False
    if filepath.stat().st_size < 50:
        return False
    return bool(_PROOF_SIGNATURE.search(txt)) or bool(
        _REQUEST_SIGNATURE.search(txt)
    )


def scan_evidence(eng_dir: Path) -> dict[str, list[Path]]:
    """Return {challenge_id: [evidence files containing its patterns]}."""
    ev_dir = eng_dir / "evidence"
    if not ev_dir.exists():
        return {}

    files = [f for f in ev_dir.rglob("*") if f.is_file()]
    challenges = json.loads(CHALLENGES_PATH.read_text())["challenges"]

    result: dict[str, list[Path]] = {}
    for ch in challenges:
        cid = ch["id"]
        pat = build_pattern(cid, ch.get("patterns", []))
        if not pat:
            continue
        hits = []
        for f in files:
            try:
                content = f.read_text(errors="replace")
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
    "vulnerability", "walkthrough", "writeup", "exploit", "solution",
    "challenge", "flag", "answer", "ctf", "hackthebox",
]
_WALKTHROUGH_RE = re.compile(
    r"\b(" + "|".join(_WALKTHROUGH_WORDS) + r")\b", re.I
)


def check_compliance(hist_text: str, evidence_count: int) -> tuple[int, bool]:
    """Return (violation_count, is_unknown)."""
    lines = [
        line for line in hist_text.splitlines() if line.strip() and not line.startswith("#")
    ]
    if not lines or len(lines) < 3:
        return (0, True)  # UNKNOWN — not enough history to assess

    hits = 0
    for line in lines:
        ll = line.lower()
        if ("duck-store" in ll or "duck store" in ll) and _WALKTHROUGH_RE.search(ll):
            hits += 1
    return (hits, False)


# ---------------------------------------------------------------------------
# Main scoring
# ---------------------------------------------------------------------------
def score_engagement(eng_dir: Path) -> dict:
    """Score one engagement directory. Returns structured result dict."""
    challenges = json.loads(CHALLENGES_PATH.read_text())

    # PTT (Fix A)
    ptt = parse_ptt(eng_dir)

    # Hypotheses (Fix C)
    hyp_text = ""
    hyp_path = eng_dir / "hypotheses.md"
    if hyp_path.exists():
        hyp_text = hyp_path.read_text()
    hypotheses = parse_hypotheses(hyp_text)
    hyp_created = len(hypotheses)
    validated_ids = validated_challenge_ids(hypotheses)

    # History + Compliance (Fix F)
    hist_text = ""
    hist_paths = [eng_dir / "state" / "history.md", eng_dir / "history.md"]
    for hp in hist_paths:
        if hp.exists():
            hist_text = hp.read_text()
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

    confirmed = []       # validated hypothesis + proof-quality evidence
    touched = []         # evidence matches but no validated hypothesis
    not_tested = []      # no evidence match
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
                confirmed_details.append({
                    "id": cid,
                    "files": [str(f.relative_to(eng_dir)) for f in proof_files],
                })
            else:
                touched.append(cid)
                touched_details.append({
                    "id": cid,
                    "reason": "evidence exists but no HTTP proof signature",
                })
        elif ev_matches:
            touched.append(cid)
            touched_details.append({
                "id": cid,
                "reason": "evidence matches but hypothesis not Validated",
            })
        else:
            not_tested.append(cid)
            missed_details.append({
                "id": cid,
                "reason": "no evidence file matches challenge patterns",
            })

    # Compliance (Fix F)
    violations, compliance_unknown = check_compliance(hist_text, ev_count)

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
COVERAGE     Confirmed  {r['confirmed']}/{total} ({round(r['confirmed']/max(total,1)*100)}%)
             Touched    {r['touched']}/{total} (evidence exists, needs validation)
             Not tested {r['not_tested']}/{total}
PTT          {r['ptt']['done']}/{r['ptt']['total']} done ({round(r['ptt']['done']/max(r['ptt']['total'],1)*100)}%)
HYPOTHESES   {r['hyp_created']} created, {r['hyp_resolved']} resolved
COMMANDS     {r['hist_lines']} ({r['hist_blocks']} blocked)
EVIDENCE     {r['ev_count']} files
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

    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: score.py <ENG_DIR> [--calibrate known-good|known-bad]")
        sys.exit(1)

    # Calibration mode (P5)
    if len(sys.argv) >= 3 and sys.argv[1] == "--calibrate":
        cmd_calibrate(sys.argv[2])

    eng_dir = Path(sys.argv[1])
    if not eng_dir.exists():
        print(f"ERROR: engagement directory not found: {eng_dir}")
        sys.exit(1)

    result = score_engagement(eng_dir)
    print_result(result)

    # Shell-friendly exit codes
    if result["confirmed"] == 0 and result["touched"] == 0:
        sys.exit(2)  # Nothing found
    if result["violations"] > 0:
        sys.exit(3)  # Compliance violations
    sys.exit(0)


if __name__ == "__main__":
    main()
