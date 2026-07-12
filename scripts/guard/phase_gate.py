"""Pure phase-completion checks for Violin engagements.

The gate reads engagement artifacts only. It never blocks target activity; callers
apply it when advancing a phase or closing an engagement.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypeAlias

Pathish: TypeAlias = str | Path

PHASE_ORDER = [
    "SCOPING",
    "RECON",
    "VULN_RESEARCH",
    "EXPLOITATION",
    "REPORTING",
    "RETROSPECTIVE",
]

# A directory requirement means at least one nested regular file with >=1 byte.
# Reports are intentionally non-trivial rather than empty/stub placeholders.
REQUIRED: dict[str, list[tuple[str, int]]] = {
    "SCOPING": [
        ("scope/scope.yaml", 1),
        ("scope/authorization.md", 1),
        ("state/ptt.md", 1),
        ("hypotheses.md", 1),
    ],
    "RECON": [("evidence/recon", 1)],
    "VULN_RESEARCH": [("evidence/vuln-research", 1)],
    "EXPLOITATION": [("evidence/exploitation", 1)],
    "REPORTING": [("evidence/reporting/report.md", 50)],
    "RETROSPECTIVE": [
        ("evidence/retrospective/retrospective.md", 50),
        ("state/phase-summary.md", 1),
        ("state/checkpoint.json", 1),
    ],
}

_PTT_PHASE_RE = re.compile(r"^##\s+Phase:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_PTT_ROW_RE = re.compile(r"^\|\s*PT-\d+\s*\|\s*\[([ x~!\-])\]", re.MULTILINE)
_VALIDATED_RE = re.compile(
    r"^\s*-\s*\*\*Status:\*\*\s*(?:Validated|Verified)\b",
    re.MULTILINE | re.IGNORECASE,
)


def normalize_phase(phase: str) -> str:
    """Return the canonical underscore-separated phase name."""
    return re.sub(r"[\s-]+", "_", (phase or "").strip().upper())


def _exists_nonempty(eng_dir: Path, rel: str, min_bytes: int) -> bool:
    path = eng_dir / rel
    if path.is_dir():
        try:
            return any(
                item.is_file() and item.stat().st_size >= min_bytes for item in path.rglob("*")
            )
        except OSError:
            return False
    try:
        return path.is_file() and path.stat().st_size >= min_bytes
    except OSError:
        return False


def _has_validated_hypothesis(eng_dir: Path) -> bool:
    path = eng_dir / "hypotheses.md"
    if not path.is_file():
        return False
    try:
        return bool(_VALIDATED_RE.search(path.read_text(encoding="utf-8", errors="replace")))
    except OSError:
        return False


def check_phase_gate(eng_dir: Pathish, phase: str) -> tuple[bool, list[str]]:
    """Return whether ``phase`` has all mandatory deliverables and any gaps."""
    eng = Path(eng_dir)
    if not eng.is_dir():
        return False, ["<eng_dir does not exist>"]

    canonical = normalize_phase(phase)
    if canonical not in REQUIRED:
        return False, [f"unknown phase '{canonical}'"]

    missing = [
        rel for rel, min_bytes in REQUIRED[canonical] if not _exists_nonempty(eng, rel, min_bytes)
    ]

    if canonical == "EXPLOITATION" and not _has_validated_hypothesis(eng):
        missing.append("hypotheses.md#status!=Validated/Verified")

    if canonical == "RETROSPECTIVE":
        checkpoint = eng / "state/checkpoint.json"
        if checkpoint.is_file():
            try:
                data = json.loads(checkpoint.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or data.get("status") != "COMPLETE":
                    missing.append("state/checkpoint.json#status!=COMPLETE")
            except (OSError, UnicodeError, json.JSONDecodeError):
                missing.append("state/checkpoint.json#unparseable")

    return not missing, missing


def check_all_phase_gates(eng_dir: Pathish) -> list[tuple[str, list[str]]]:
    """Return every phase whose completion gate is not satisfied."""
    failed: list[tuple[str, list[str]]] = []
    for phase in PHASE_ORDER:
        ok, missing = check_phase_gate(eng_dir, phase)
        if not ok:
            failed.append((phase, missing))
    return failed


def _ptt_phase_statuses(eng_dir: Pathish) -> dict[str, list[str]]:
    path = Path(eng_dir) / "state/ptt.md"
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    matches = list(_PTT_PHASE_RE.finditer(text))
    sections: dict[str, list[str]] = {}
    for index, match in enumerate(matches):
        phase = normalize_phase(match.group(1))
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[phase] = _PTT_ROW_RE.findall(text[match.end() : end])
    return sections


def closure_requested_from_ptt(eng_dir: Pathish) -> bool:
    """True only when all REPORTING and RETROSPECTIVE PTT rows are ``[x]``."""
    sections = _ptt_phase_statuses(eng_dir)
    for phase in ("REPORTING", "RETROSPECTIVE"):
        statuses = sections.get(phase, [])
        if not statuses or any(status.lower() != "x" for status in statuses):
            return False
    return True


def current_phase_from_ptt(eng_dir: Pathish) -> str:
    """Derive the earliest phase with unfinished PTT work, best-effort."""
    sections = _ptt_phase_statuses(eng_dir)
    for phase in PHASE_ORDER:
        statuses = sections.get(phase)
        if not statuses or any(status.lower() not in {"x", "-"} for status in statuses):
            return phase
    return PHASE_ORDER[-1]
