"""Hypothesis board parsing, validation, and mutation.

Canonical states: Candidate, Likely, Validated, Rejected.
Legacy aliases: Researching->Candidate, Verified->Validated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

__all__ = [
    "Hypothesis",
    "HypothesisValidationResult",
    "parse_hypotheses",
    "validate_hypotheses",
    "find_by_service_port",
    "update_hypothesis",
    "needs_hypothesis",
]

# Canonical states
CANONICAL_STATES = ("Candidate", "Likely", "Validated", "Rejected")
LEGACY_ALIASES = {
    "Researching": "Candidate",
    "Verified": "Validated",
}
ALL_STATES = CANONICAL_STATES + tuple(LEGACY_ALIASES.keys())

_HYPOTHESIS_RE = re.compile(
    r"^###\s+H-(?P<id>\d+)\s*:\s*(?P<title>[^\n]+)\n"
    r"(?:- \*\*Status:\*\*\s*(?P<status>[^\n]+)\n)?"
    r"(?:- \*\*Phase:\*\*\s*(?P<phase>[^\n]+)\n)?"
    r"(?:- \*\*Service:\*\*\s*(?P<service>[^\n]+)\n)?"
    r"(?:- \*\*Port:\*\*\s*(?P<port>[^\n]+)\n)?"
    r"(?:- \*\*Target:\*\*\s*(?P<target>[^\n]+)\n)?"
    r"(?:- \*\*Vuln Class:\*\*\s*(?P<vuln_class>[^\n]+)\n)?"
    r"(?:- \*\*Rationale:\*\*\s*(?P<rationale>[^\n]+)\n)?"
    r"(?:- \*\*Evidence:\*\*\s*(?P<evidence>[^\n]+)\n)?"
    r"(?:- \*\*Updated:\*\*\s*(?P<updated>[^\n]+)\n)?",
    re.MULTILINE,
)


@dataclass
class Hypothesis:
    id: str
    title: str
    status: str = "Candidate"
    phase: str = ""
    service: str = ""
    port: str = ""
    target: str = ""
    vuln_class: str = ""
    rationale: str = ""
    evidence: str = ""
    updated: str = ""

    def canonical_status(self) -> str:
        return LEGACY_ALIASES.get(self.status, self.status)

    def to_markdown(self) -> str:
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        lines = [f"### H-{self.id}: {self.title}"]
        lines.append(f"- **Status:** {self.canonical_status()}")
        if self.phase:
            lines.append(f"- **Phase:** {self.phase}")
        if self.service:
            lines.append(f"- **Service:** {self.service}")
        if self.port:
            lines.append(f"- **Port:** {self.port}")
        if self.target:
            lines.append(f"- **Target:** {self.target}")
        if self.vuln_class:
            lines.append(f"- **Vuln Class:** {self.vuln_class}")
        if self.rationale:
            lines.append(f"- **Rationale:** {self.rationale}")
        if self.evidence:
            lines.append(f"- **Evidence:** {self.evidence}")
        lines.append(f"- **Updated:** {self.updated or now} UTC")
        return "\n".join(lines) + "\n"


@dataclass
class HypothesisValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0


def _normalize_status(status: str) -> str:
    return LEGACY_ALIASES.get(status.strip(), status.strip())


def parse_hypotheses(path: Path) -> list[Hypothesis]:
    """Parse hypotheses.md into a list of Hypothesis objects.

    HTML comments (e.g. template instructions wrapped in ``<!-- ... -->``) are
    stripped before parsing so placeholder examples in templates are never
    mistaken for real hypotheses.
    """
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8")
    content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
    hypotheses = []
    for match in _HYPOTHESIS_RE.finditer(content):
        h = Hypothesis(
            id=match.group("id"),
            title=match.group("title").strip(),
            status=_normalize_status(match.group("status") or "Candidate"),
            phase=(match.group("phase") or "").strip(),
            service=(match.group("service") or "").strip(),
            port=(match.group("port") or "").strip(),
            target=(match.group("target") or "").strip(),
            vuln_class=(match.group("vuln_class") or "").strip(),
            rationale=(match.group("rationale") or "").strip(),
            evidence=(match.group("evidence") or "").strip(),
            updated=(match.group("updated") or "").strip(),
        )
        hypotheses.append(h)
    return hypotheses


def validate_hypotheses(hypotheses: list[Hypothesis]) -> HypothesisValidationResult:
    """Validate a list of hypotheses."""
    result = HypothesisValidationResult(hypotheses=hypotheses)
    seen_ids = set()
    for h in hypotheses:
        if h.id in seen_ids:
            result.add_error(f"duplicate hypothesis ID: H-{h.id}")
        seen_ids.add(h.id)
        if h.canonical_status() not in CANONICAL_STATES:
            result.add_warning(f"H-{h.id}: non-canonical status '{h.status}'")
        if not h.title:
            result.add_error(f"H-{h.id}: missing title")
        if not h.service and not h.port:
            result.add_warning(f"H-{h.id}: missing service and port")
    return result


def find_by_service_port(
    hypotheses: list[Hypothesis], service: str, port: str
) -> Hypothesis | None:
    """Find a hypothesis matching service and port (exact match)."""
    for h in hypotheses:
        if h.service.lower() == service.lower() and h.port == port:
            return h
    return None


def update_hypothesis(path: Path, **fields: Any) -> Hypothesis:
    """Update a hypothesis in the file by ID (creates if missing)."""
    hypotheses = parse_hypotheses(path)
    h_id = str(fields.get("id", "")).strip()
    if not h_id:
        raise ValueError("id is required")

    # Find existing
    target = None
    for h in hypotheses:
        if h.id == h_id:
            target = h
            break

    if target is None:
        # Create new
        target = Hypothesis(id=h_id, title=fields.get("title", f"Hypothesis {h_id}"))
        hypotheses.append(target)

    # Update fields
    for key, value in fields.items():
        if key == "id":
            continue
        if hasattr(target, key):
            setattr(target, key, value)

    # Always update timestamp
    target.updated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")

    # Rewrite file
    _rewrite_hypotheses(path, hypotheses)
    return target


def _rewrite_hypotheses(path: Path, hypotheses: list[Hypothesis]) -> None:
    """Rewrite the entire hypotheses file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    template = (
        path.read_text(encoding="utf-8") if path.exists() else "# Hypothesis Board\n\n"
    )
    # Keep any header content before first hypothesis
    header_end = template.find("### H-")
    if header_end == -1:
        header = template.strip() + "\n\n"
    else:
        header = template[:header_end].rstrip() + "\n\n"

    body = "\n".join(h.to_markdown() for h in hypotheses)
    path.write_text(header + body, encoding="utf-8")


def needs_hypothesis(phase: str) -> bool:
    """Return True if the phase requires hypotheses (vuln-research/exploitation)."""
    phase_lower = phase.lower().replace("-", "_")
    return phase_lower in ("vuln_research", "exploitation")