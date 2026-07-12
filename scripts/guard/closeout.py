"""Close-out gates: enforce the mandatory REPORTING / RETROSPECTIVE artifacts.

These are HARD gates (ERROR → exit 1). Unlike the advisory freshness warnings
in ``freshness.py`` (which are WARNING → exit 2 and *are* auto-approved under
``--yolo``), close-out violations map to ``denied`` even when
``HERMES_YOLO_MODE=1`` (see ``plugins/violin_guard/tools.py``). That is
deliberate: skipping REPORTING/RETROSPECTIVE is a skill-level violation — the
compliance audit found a prior engagement stopped at flag capture with no
report, no retrospective, no phase-summary, no CVSS vectors, and an empty
Research Log, because those artifacts were only ever emitted as yolo-approved
warnings.

Artifacts enforced (skill-defined paths):
  - REPORTING  : $ENG_DIR/reporting/report.md (non-trivial),
                 $ENG_DIR/state/phase-summary.md (transition summary),
                 CVSS:3.1 vector for any Critical/High finding,
                 non-empty hypotheses.md "Research Log" (RES- entries).
  - RETROSPECTIVE: $ENG_DIR/retrospective.md (or evidence/retrospective/...),
                 phase-summary.md still present, CVSS still required.
"""

from __future__ import annotations

import re
from pathlib import Path

from guard.core import CheckResult

# Candidate locations for the mandated artifacts (skill-defined).
REPORT_CANDIDATES = [
    "reporting/report.md",
    "evidence/reporting/report.md",
    "report.md",
]
RETRO_CANDIDATES = [
    "retrospective.md",
    "evidence/retrospective/retrospective.md",
    "reporting/retrospective.md",
]
PHASE_SUMMARY = "state/phase-summary.md"

CVSS_RE = re.compile(r"CVSS:3\.1", re.IGNORECASE)
SEVERITY_RE = re.compile(r"(?i)severity\s*[:=]?\s*(critical|high)\b")
TIER_RE = re.compile(r"\b(L3|L4)\b")

# Commands that legitimately PRODUCE close-out artifacts, or are guard
# housekeeping — never blocked by the close-out gate, so the agent can create
# the very file the gate requires without deadlocking.
_REPORT_TOKENS = (
    "report.md", "retrospective.md", "phase-summary.md",
    "report-template", "coverage-matrix", "retrospective",
)
_WRITE_OPS = (
    "write_file", "record-ptt", "record-hypothesis", "record-history",
    "tee ", "cat >", "cat >>", "echo >", "echo >>", "printf >",
    "sed -i", "vim ", "nano ",
)
_SAFE_META = (
    "violin_guard.py", "hypothesis_guard.py", "sync-done", "heartbeat-done",
    "message-tick", "check-command", "check-closeout", "check-bootstrap",
)


def _exists_nonempty(eng_dir: Path, rel: str, min_bytes: int) -> bool:
    p = eng_dir / rel
    if not p.exists() or not p.is_file():
        return False
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return text.strip() != "" and p.stat().st_size >= min_bytes


def _report_substantive(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    # Accept if it carries a CVSS vector (the key mandate) or a standard
    # report section. Rejects empty/stub files.
    if "cvss" in text:
        return True
    return any(tok in text for tok in ("severity", "finding", "summary", "methodology"))


def _report_ok(eng_dir: Path) -> bool:
    for rel in REPORT_CANDIDATES:
        if _exists_nonempty(eng_dir, rel, 50) and _report_substantive(eng_dir / rel):
            return True
    return False


def _retro_ok(eng_dir: Path) -> bool:
    for rel in RETRO_CANDIDATES:
        if _exists_nonempty(eng_dir, rel, 30):
            return True
    return False


def _phase_summary_ok(eng_dir: Path) -> bool:
    return _exists_nonempty(eng_dir, PHASE_SUMMARY, 30)


def _cvss_ok(eng_dir: Path) -> bool:
    """True if no Critical/High/L3/L4 finding lacks a CVSS:3.1 vector."""
    candidates = [
        eng_dir / "evidence" / "vuln-research" / "findings.md",
        eng_dir / "evidence" / "findings.md",
        eng_dir / "state" / "findings.md",
        eng_dir / "reporting" / "report.md",
        eng_dir / "evidence" / "reporting" / "report.md",
    ]
    found = [p for p in candidates if _exists_nonempty(p.parent, p.name, 1)]
    if not found:
        return True  # no findings recorded -> nothing to score
    combined = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in found)
    if CVSS_RE.search(combined):
        return True
    # No CVSS vector present: only a problem if a high-severity finding exists.
    return not (SEVERITY_RE.search(combined) or TIER_RE.search(combined))


def _research_log_ok(hyp_path: Path) -> bool:
    if not hyp_path.exists() or not hyp_path.is_file():
        return False
    text = hyp_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"##\s+Research Log", text)
    if not m:
        return False
    tail = text[m.end():]
    nxt = re.search(r"\n##\s+", tail)
    section = tail[: nxt.start()] if nxt else tail
    return bool(re.search(r"RES-\d+", section))


def _is_permitted(command: str) -> bool:
    """True when the command is producing a close-out artifact or is guard
    housekeeping — so it must NOT be blocked by the close-out gate."""
    c = command.lower()
    if any(tok in c for tok in _REPORT_TOKENS):
        return True
    if any(op in c for op in _WRITE_OPS):
        return True
    if re.search(r">\s*\S*\.md(\b|$)", c):
        return True
    if any(meta in c for meta in _SAFE_META):
        return True
    return False


def check_closeout(eng_dir: str | Path, phase: str, command: str = "") -> CheckResult:
    """Hard gate for the mandatory close-out artifacts.

    Returns a ``CheckResult`` whose ``.errors`` are non-empty (→ exit 1 →
    ``denied`` even under yolo) when a mandated artifact is missing *and* the
    command is not the one producing it.
    """
    result = CheckResult()
    eng = Path(eng_dir)
    phase = phase.upper().replace("-", "_")
    permitted = _is_permitted(command or "")

    if phase == "REPORTING":
        # REPORTING is documentation-only. When the agent is running an
        # artifact-producing command, accept it and re-check after save (no
        # deadlock). Otherwise every missing artifact is a hard BLOCK.
        if permitted:
            result.add_info(
                "close-out (REPORTING) command accepted — produce "
                "state/phase-summary.md, reporting/report.md (with CVSS:3.1 "
                "vectors for Critical/High findings), and a Research Log entry, "
                "then re-run check-command."
            )
        else:
            if not _phase_summary_ok(eng):
                result.add_error(
                    "close-out gate: state/phase-summary.md missing/empty — write the "
                    "RECON→VULN-RESEARCH→EXPLOITATION→REPORTING transition summary before proceeding"
                )
            if not _report_ok(eng):
                result.add_error(
                    "close-out gate: reporting/report.md not produced — REPORTING is "
                    "documentation-only; create the report before any other command"
                )
            if not _cvss_ok(eng):
                result.add_error(
                    "close-out gate: a Critical/High (L3/L4) finding is present but no "
                    "CVSS:3.1 vector is recorded — add CVSS vectors before reporting"
                )
            if not _research_log_ok(eng / "hypotheses.md"):
                result.add_error(
                    "close-out gate: hypotheses.md 'Research Log' has no RES- entries — "
                    "record the research loop (NVD/ExploitDB/…) before reporting"
                )

    elif phase == "RETROSPECTIVE":
        if not _phase_summary_ok(eng):
            result.add_error(
                "close-out gate: state/phase-summary.md missing/empty for retrospective"
            )
        if not _retro_ok(eng):
            if permitted:
                result.add_info("retrospective-production command accepted; re-run check-command after saving")
            else:
                result.add_error(
                    "close-out gate: retrospective.md not produced — RETROSPECTIVE is "
                    "mandatory after every engagement"
                )
        if not _report_ok(eng):
            result.add_error(
                "close-out gate: reporting/report.md missing — complete REPORTING before RETROSPECTIVE"
            )
        if not _cvss_ok(eng):
            result.add_error(
                "close-out gate: a Critical/High (L3/L4) finding lacks a CVSS:3.1 vector"
            )

    return result
