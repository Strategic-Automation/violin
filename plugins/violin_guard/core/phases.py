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
    "allowed_transitions",
    "validate_transition",
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


# Aliases accepted from user input
_ALIASES = {
    "vuln-research": Phase.VULN_RESEARCH,
    "vuln_research": Phase.VULN_RESEARCH,
    "post-exploitation": Phase.POST_EXPLOITATION,
    "post_exploitation": Phase.POST_EXPLOITATION,
    "privesc": Phase.PRIVESC,
    "private-esc": Phase.PRIVESC,
    "flag": Phase.FLAGS,
    "capture-flags": Phase.FLAGS,
}


def normalize_phase(s: str) -> Phase:
    """Normalize a phase string to a Phase enum, accepting aliases."""
    key = s.strip().upper().replace("-", "_")
    try:
        return Phase[key]
    except KeyError:
        pass
    # Try aliases
    for alias, phase in _ALIASES.items():
        if s.lower().replace("-", "_") == alias:
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


# Allowed transitions: from_phase -> set of allowed to_phases
ALLOWED_TRANSITIONS: dict[Phase, set[Phase]] = {
    Phase.SCOPING: {Phase.RECON},
    Phase.RECON: {Phase.VULN_RESEARCH, Phase.SCOPING},
    Phase.VULN_RESEARCH: {Phase.EXPLOITATION, Phase.RECON, Phase.SCOPING},
    Phase.EXPLOITATION: {
        Phase.POST_EXPLOITATION,
        Phase.PRIVESC,
        Phase.FLAGS,
        Phase.VULN_RESEARCH,
        Phase.REPORTING,
    },
    Phase.POST_EXPLOITATION: {
        Phase.PRIVESC,
        Phase.FLAGS,
        Phase.EXPLOITATION,
        Phase.REPORTING,
    },
    Phase.PRIVESC: {Phase.FLAGS, Phase.REPORTING, Phase.RETROSPECTIVE, Phase.EXPLOITATION},
    Phase.FLAGS: {Phase.REPORTING, Phase.RETROSPECTIVE, Phase.PRIVESC},
    Phase.REPORTING: {Phase.RETROSPECTIVE},
    Phase.RETROSPECTIVE: set(),
}


def allowed_transitions(from_phase: Phase) -> set[Phase]:
    """Return the set of phases that can be transitioned to from the given phase."""
    return ALLOWED_TRANSITIONS.get(from_phase, set())


def validate_transition(from_phase: Phase, to_phase: Phase) -> bool:
    """Return True if the transition is allowed."""
    return to_phase in allowed_transitions(from_phase)
