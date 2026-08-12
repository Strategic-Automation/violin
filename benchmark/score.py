#!/usr/bin/env python3
"""score.py [$ENG_DIR] — evidence-gated Violin benchmark scorer.

Fixes A–F, P5, D5 applied:
  A  — PTT path corrected (state/ptt.md)
  B  — Evidence-gated: challenge counts ONLY if Validated hypothesis Links it
  C  — Hypothesis status parsed per-block, not substring-matched
  D  — Duck-Store hint walkthrough compliance checker (D5)
  E  — totals_by_challenge uses confirmed hypotheses, not completed puzzles
  F  — removed stale is_puzzle_complete; everything flows through parse_hypotheses
  P5 — CLI calibrate confirmed+violations output
  D5 — Compliance checker + calibration

Design: parse H-XXX blocks with per-block regex. Only "Validated" blocks
contribute challenge counts.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHALLENGES = {
    "A01": "Injection",
    "A02": "Broken Authentication",
    "A03": "Sensitive Data Exposure",
    "A04": "XXE",
    "A05": "Broken Access Control",
    "A06": "Security Misconfiguration",
    "A07": "XSS",
    "A08": "Insecure Deserialization",
    "A09": "Vulnerable Components",
    "A10": "Logging & Monitoring",
    "A11": "SSRF",
    "A12": "IDOR",
    "A13": "Mass Assignment",
    "A14": "Open Redirect",
}

ALL_CHALLENGE_IDS = frozenset(CHALLENGES)

# Ordered list for consistent reporting
CHALLENGE_ID_LIST = sorted(ALL_CHALLENGE_IDS)

TASKS: dict[str, str] = {
    "PT-001": "Recon", "PT-002": "Scanning", "PT-003": "Enumeration",
    "PT-004": "Exploitation", "PT-005": "Post-Exploitation",
    "PT-006": "Report Writing", "PT-007": "Report Delivery",
    "PT-008": "Remediation Advice", "PT-009": "Retesting",
    "PT-010": "Closeout",
}

# Walkthrough / duck-store compliance words
_WALKTHROUGH_WORDS = [
    "vulnerability", "walkthrough", "writeup", "exploit",
    "solution", "challenge", "flag", "answer", "ctf", "hackthebox",
]
_WALKTHROUGH_RE = re.compile(r"\b(" + "|".join(_WALKTHROUGH_WORDS) + r")\"b", re.I)
_DUCKSTORE_RE = re.compile(r"\b(duck-store|duck store)\b", re.I)

ENG_STATE_DIR = "state"
KNOWN_GOOD_PATH = Path("benchmark/calibration/known-good")
KNOWN_BAD_PATH = Path("benchmark/calibration/known-bad")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class ScoreResult:
    eng_dir: str = ""
    confirmed: int = 0
    touched: int = 0
    blocked: int = 0
    illegal: int = 0
    total_by_challenge: Dict[str, int] = field(default_factory=dict)
    challenge_hits: Dict[str, set[str]] = field(default_factory=dict)
    violations: int = 0
    violation_details: List[str] = field(default_factory=list)
    hypotheses_total: int = 0
    hypotheses_validated: int = 0


def parse_hypotheses(text: str) -> list[dict]:
    """Parse each ### H-XXX: block, extract Status and Linked challenges."""
    if not text or not text.strip():
        return []
    # Split on newline immediately before ### H-XXX:
    # The colon must be inside the lookahead so it is not consumed by the split.
    blocks = re.split(r"\n(?=### H-\d+:)", text)
    results: list[dict] = []
    for block in blocks:
        if not block.strip():
            continue
        m = re.match(r"^### (H-\d+):", block)
        if not m:
            continue
        hid = m.group(1)
        status = ""
        linked = []
        for line in block.splitlines():
            ls = line.strip()
            if ls.lower().startswith("**status:**"):
                # Extract after the colon
                parts = ls.split(":", 1)
                status = parts[1].strip() if len(parts) > 1 else ""
            elif ls.lower().startswith("**linked"):
                # e.g. **Linked challenges:** A01, A02
                idx = ls.find(":")
                if idx != -1:
                    raw = ls[idx + 1:]
                    for token in re.split(r"[,;\s]+", raw):
                        token = token.strip().upper()
                        if token in ALL_CHALLENGE_IDS:
                            linked.append(token)
        results.append({
            "hid": hid,
            "status": status,
            "linked": linked,
        })
    return results


def check_compliance(hist_text: str) -> tuple[int, bool]:
    """Return (violation_count, is_unknown)."""
    lines = [line for line in hist_text.splitlines() if line.strip() and not line.startswith("#")]
    if not lines or len(lines) < 3:
        return (0, True)  # UNKNOWN — not enough history to assess

    hits = 0
    for line in lines:
        ll = line.lower()
        if ("duck-store" in ll or "duck store" in ll) and _WALKTHROUGH_RE.search(ll):
            hits += 1
    return (hits, False)


def score_engagement(eng_dir: str | Path) -> ScoreResult:
    """Score a single engagement directory."""
    eng_dir = Path(eng_dir)
    result = ScoreResult(eng_dir=str(eng_dir))

    # --- Hypothesis block parsing (C, F) ---
    hypo_path = eng_dir / ENG_STATE_DIR / "hypotheses.md"
    if hypo_path.exists():
        try:
            text = hypo_path.read_text(encoding="utf-8")
            hypos = parse_hypotheses(text)
            result.hypotheses_total = len(hypos)
            for h in hypos:
                if h["status"].strip().lower() in ("validated",):
                    result.hypotheses_validated += 1
                    for cid in h["linked"]:
                        if cid not in result.challenge_hits:
                            result.challenge_hits[cid] = set()
                        result.challenge_hits[cid].add(h["hid"])
        except Exception:
            pass

    # --- PTT task tracking (A) ---
    ptt_path = eng_dir / ENG_STATE_DIR / "ptt.md"
    if ptt_path.exists():
        try:
            ptt_text = ptt_path.read_text(encoding="utf-8")
            for tid, label in TASKS.items():
                if tid in ptt_text:
                    result.touched += 1
        except Exception:
            pass

    # --- Challenge completion from validated hypotheses (B, E) ---
    for cid, hids in result.challenge_hits.items():
        result.total_by_challenge[cid] = len(hids)
    result.confirmed = len(result.challenge_hits)

    # --- Compliance check (D5) ---
    hist_path = eng_dir / ENG_STATE_DIR / "command_history.md"
    if hist_path.exists():
        try:
            hist_text = hist_path.read_text(encoding="utf-8")
            vios, is_unk = check_compliance(hist_text)
            result.violations = vios
            if vios > 0:
                result.violation_details = [f"Duck Store walkthrough hints detected: {vios} hits"]
            if is_unk:
                result.violation_details.append("Compliance unknown — insufficient history data")
        except Exception:
            pass

    return result


def print_result(result: ScoreResult) -> None:
    """Print human-readable score result."""
    print(f"=== SCORE for {result.eng_dir} ===")
    print(f"Hypotheses: {result.hypotheses_validated}/{result.hypotheses_total} Validated")
    print(f"Confirmed challenges: {result.confirmed}")
    print("Challenge breakdown:")
    for cid in CHALLENGE_ID_LIST:
        count = result.total_by_challenge.get(cid, 0)
        if count > 0:
            print(f"  {cid} ({CHALLENGES.get(cid, 'Unknown')}): {count}")
    print(f"Touched tasks: {result.touched}")
    print(f"Compliance violations: {result.violations}")
    if result.violation_details:
        for detail in result.violation_details:
            print(f"  - {detail}")


def cmd_calibrate(kind: str) -> None:
    """Score a known-good or known-bad engagement to verify the scorer itself."""
    target = {"good": KNOWN_GOOD_PATH, "bad": KNOWN_BAD_PATH}.get(kind)
    if not target or not target.exists():
        print(f"ERROR: calibration target not found: {target}")
        print("Create calibration engagements with all 14 confirmed and 0 confirmed respectively.")
        sys.exit(1)
    print(f"=== CALIBRATION: known-{kind} at {target} ===")
    result = score_engagement(target)
    print_result(result)

    if kind == "good":
        if result.confirmed >= 14:
            print("PASS: known-good has 14 confirmed")
        else:
            print(f"FAIL: known-good has {result.confirmed} confirmed, expected 14")
            sys.exit(1)
        if result.violations == 0:
            print("PASS: known-good has 0 violations")
        else:
            print(f"FAIL: known-good has {result.violations} violations, expected 0")
            sys.exit(1)
    else:
        if result.confirmed == 0:
            print("PASS: known-bad has 0 confirmed")
        else:
            print(f"FAIL: known-bad has {result.confirmed} confirmed, expected 0")
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Violin Benchmark Scorer")
    parser.add_argument("eng_dir", nargs="?", default=".",
                        help="Engagement directory (default: .)")
    parser.add_argument("--calibrate", choices=["good", "bad"],
                        help="Run a calibration check")
    args = parser.parse_args()

    if args.calibrate:
        cmd_calibrate(args.calibrate)
        return

    eng_dir = Path(args.eng_dir) if args.eng_dir else Path(".")
    if not eng_dir.exists():
        print(f"ERROR: directory not found: {eng_dir}")
        sys.exit(1)

    result = score_engagement(eng_dir)
    print_result(result)

    # Shell-friendly exit codes
    if result.confirmed == 0 and result.touched == 0:
        sys.exit(2)  # Nothing found
    if result.violations > 0:
        sys.exit(3)  # Compliance violations
    sys.exit(0)


if __name__ == "__main__":
    main()