"""Phase enumeration and phase-gate logic.

Phases: SCOPING, RECON, VULN_RESEARCH, EXPLOITATION, POST_EXPLOITATION,
PRIVESC, FLAGS, REPORTING, RETROSPECTIVE.

Pure functions — no subprocess.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "Phase",
    "normalize_phase",
    "requires_hypothesis",
    "suppresses_heartbeat",
]


class Phase(str, Enum):
    SCOPING = "SCOPING"
    RECON = "RECON"
    VULN_RESEARCH = "VULN_RESEARCH"
    EXPLOITATION = "EXPLOITATION"
    POST_EXPLOITATION = "POST_EXPLOITATION"
    PRIVESC = "PRIVESC"
    FLAGS = "FLAGS"
    REPORTING = "REPORTING"
    RETROSPECTIVE = "RETROSPECTIVE"


# Unified lookup: canonical enum names + aliases, all normalised to
# UPPER_UNDERSCORE so the caller only needs one dict hit.
_PHASE_LOOKUP: dict[str, Phase] = {p.value: p for p in Phase}
_PHASE_LOOKUP.update(
    {
        "VULN_RESEARCH": Phase.VULN_RESEARCH,
        "POST_EXPLOITATION": Phase.POST_EXPLOITATION,
        "PRIVESC": Phase.PRIVESC,
        "PRIVATE_ESC": Phase.PRIVESC,
        "FLAG": Phase.FLAGS,
        "CAPTURE_FLAGS": Phase.FLAGS,
    }
)


def normalize_phase(s: str) -> Phase:
    """Normalize a phase string to a Phase enum, accepting aliases."""
    key = s.strip().upper().replace("-", "_")
    phase = _PHASE_LOOKUP.get(key)
    if phase is not None:
        return phase
    raise ValueError(f"unknown phase: {s}")


def requires_hypothesis(phase: Phase) -> bool:
    """Return True if the phase requires active hypotheses."""
    return phase in (
        Phase.VULN_RESEARCH,
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.PRIVESC,
        Phase.FLAGS,
    )


def suppresses_heartbeat(phase: Phase) -> bool:
    """Return True if heartbeat is suppressed in this phase."""
    return phase in (Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.PRIVESC, Phase.FLAGS)
