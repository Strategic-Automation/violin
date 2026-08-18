"""Phase enumeration and phase-gate logic.

Phases: SCOPING, RECON, VULN_RESEARCH, EXPLOITATION, POST_EXPLOITATION,
PRIVESC, FLAGS, REPORTING, RETROSPECTIVE.

Pure functions — no subprocess.
"""

from __future__ import annotations

from enum import Enum


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


__all__ = [
    "Phase",
    "normalize_phase",
    "requires_hypothesis",
    "suppresses_heartbeat",
    "can_advance_phase",
]

# Ordered phase progression for auto-advance logic
_PHASE_ORDER = [
    Phase.SCOPING,
    Phase.RECON,
    Phase.VULN_RESEARCH,
    Phase.EXPLOITATION,
    Phase.POST_EXPLOITATION,
    Phase.PRIVESC,
    Phase.FLAGS,
    Phase.REPORTING,
    Phase.RETROSPECTIVE,
]
_PHASE_INDEX = {p: i for i, p in enumerate(_PHASE_ORDER)}


def can_advance_phase(current_phase: str, requested_phase: str) -> bool:
    """Whether the requested phase is a forward transition from the current phase."""
    try:
        current = normalize_phase(current_phase)
        requested = normalize_phase(requested_phase)
    except KeyError:
        return False
    return _PHASE_INDEX.get(requested, -1) > _PHASE_INDEX.get(current, -1)


# Unified lookup: canonical enum names + aliases, all normalized to
# UPPER_UNDERSCORE so the caller only needs one dict hit.
_PHASE_LOOKUP: dict[str, Phase] = {phase.value: phase for phase in Phase}
_PHASE_LOOKUP.update(
    {
        "VULN_RESEARCH": Phase.VULN_RESEARCH,
        "VULN RESEARCH": Phase.VULN_RESEARCH,
        "POST_EXPLOITATION": Phase.POST_EXPLOITATION,
        "PRIVESC": Phase.PRIVESC,
        "PRIVATE_ESC": Phase.PRIVESC,
        "FLAG": Phase.FLAGS,
        "CAPTURE_FLAGS": Phase.FLAGS,
    }
)


def normalize_phase(phase_name: str) -> Phase:
    """Normalize a phase string to a Phase enum, accepting aliases."""
    key = phase_name.strip().upper().replace("-", "_")
    phase = _PHASE_LOOKUP.get(key)
    if phase is not None:
        return phase
    raise ValueError(f"unknown phase: {phase_name}")


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
    return phase in (
        Phase.VULN_RESEARCH,
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.PRIVESC,
        Phase.FLAGS,
    )
