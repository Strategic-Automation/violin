"""Hypothesis board parsing, validation, and mutation.

Canonical states: Candidate, Likely, Validated, Rejected.
Legacy aliases: Researching->Candidate, Verified->Validated.

Records are scope/phase bound: a hypothesis must carry a canonical status, a
valid phase, and a target that is in scope (audit P1-hyp).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .phases import normalize_phase
from .targets import normalise_target

__all__ = [
    "Hypothesis",
    "HypothesisValidationResult",
    "parse_hypotheses",
    "validate_hypotheses",
    "find_by_service_port",
    "update_hypothesis",
    "validate_hypothesis_record",
    "needs_hypothesis",
]

# Canonical states
CANONICAL_STATES = ("Candidate", "Likely", "Validated", "Rejected")
LEGACY_ALIASES = {
    "Researching": "Candidate",
    "Verified": "Validated",
}
ALL_STATES = CANONICAL_STATES + tuple(LEGACY_ALIASES.keys())

_FIELD_NAMES = {
    "status": "status",
    "phase": "phase",
    "service": "service",
    "port": "port",
    "target": "target",
    "vuln class": "vuln_class",
    "rationale": "rationale",
    "evidence": "evidence",
    "cve research": "cve_research",
    "exploit research": "exploit_research",
    "test command": "test_command",
    "test response": "test_response",
    "verification status": "verification_status",
    "rejection reason": "rejection_reason",
    "updated": "updated",
}


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
    cve_research: str = ""
    exploit_research: str = ""
    test_command: str = ""
    test_response: str = ""
    verification_status: str = ""
    rejection_reason: str = ""
    updated: str = ""

    def canonical_status(self) -> str:
        return LEGACY_ALIASES.get(self.status, self.status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.canonical_status(),
            "phase": self.phase,
            "service": self.service,
            "port": self.port,
            "target": self.target,
            "vuln_class": self.vuln_class,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "cve_research": self.cve_research,
            "exploit_research": self.exploit_research,
            "test_command": self.test_command,
            "test_response": self.test_response,
            "verification_status": self.verification_status,
            "rejection_reason": self.rejection_reason,
            "updated": self.updated,
        }

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
        if self.cve_research:
            lines.append(f"- **CVE Research:** {self.cve_research}")
        if self.exploit_research:
            lines.append(f"- **Exploit Research:** {self.exploit_research}")
        if self.test_command:
            lines.append(f"- **Test Command:** {self.test_command}")
        if self.test_response:
            lines.append(f"- **Test Response:** {self.test_response}")
        if self.verification_status:
            lines.append(f"- **Verification Status:** {self.verification_status}")
        if self.rejection_reason:
            lines.append(f"- **Rejection Reason:** {self.rejection_reason}")
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


def _normalise_id(value: Any) -> str:
    """Accept user-facing H-001 forms but persist the canonical numeric ID."""

    normalized = str(value or "").strip()
    while normalized.upper().startswith("H-"):
        normalized = normalized[2:].strip()
    if not normalized:
        return ""
    if not normalized.isdigit():
        raise ValueError("hypothesis id must be numeric or in the form H-001")
    return normalized.zfill(3)


def parse_hypotheses(path: Path) -> list[Hypothesis]:
    """Parse hypothesis headings and recognised fields in any field order."""
    if not path.exists():
        return []
    records: list[Hypothesis] = []
    current: Hypothesis | None = None
    in_comment = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if "<!--" in line:
            in_comment = True
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        heading = _parse_heading(line)
        if heading:
            if current:
                records.append(current)
            current = heading
            continue
        if current:
            _apply_field(current, line)
    if current:
        records.append(current)
    return records


def _parse_heading(line: str) -> Hypothesis | None:
    if not line.startswith("### H-"):
        return None
    identifier, separator, title = line.removeprefix("### H-").partition(":")
    if not separator or not identifier.strip().isdigit() or not title.strip():
        return None
    return Hypothesis(id=identifier.strip(), title=title.strip())


def _apply_field(hypothesis: Hypothesis, line: str) -> None:
    if not line.startswith("- **"):
        return
    label, separator, value = line.removeprefix("- **").partition(":")
    if not separator:
        return
    label = label.removesuffix("**")
    value = value.removeprefix("**")
    field = _FIELD_NAMES.get(label.strip().lower())
    if field:
        setattr(
            hypothesis,
            field,
            _normalize_status(value.strip()) if field == "status" else value.strip(),
        )


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
        for error in _validate_rejection_fields(h.to_dict()):
            result.add_error(f"H-{h.id}: {error}")
    return result


def _validate_rejection_fields(fields: dict[str, Any]) -> list[str]:
    """Keep uncertain or undocumented failures from becoming permanent rejections."""

    if _normalize_status(str(fields.get("status") or "Candidate")) != "Rejected":
        return []

    errors: list[str] = []
    verification_status = str(fields.get("verification_status") or "").strip()
    if verification_status not in {"syntax_confirmed", "not_implemented"}:
        errors.append(
            "Rejected requires verification_status syntax_confirmed or not_implemented; "
            "syntax_uncertain/not_tested must remain active for re-test"
        )
    for field_name in ("test_command", "test_response", "rejection_reason"):
        if not str(fields.get(field_name) or "").strip():
            errors.append(f"Rejected requires {field_name}")
    return errors


def find_by_service_port(
    hypotheses: list[Hypothesis], service: str, port: str
) -> Hypothesis | None:
    """Find a hypothesis matching service and port (exact match)."""
    for h in hypotheses:
        if h.service.lower() == service.lower() and h.port == port:
            return h
    return None


def validate_hypothesis_record(
    fields: dict[str, Any], in_scope_hosts: set[str] | None = None
) -> list[str]:
    """Audit P1-hyp: fail-closed validation of a hypothesis record before write.

    Returns a list of error strings (empty == valid). Enforces:
      - canonical status (legacy aliases accepted, but never arbitrary text);
      - a valid phase enum value when a phase is supplied;
      - when the record carries a target, that target must be in scope
        (``in_scope_hosts`` is provided by the caller from scope.yaml; ``None``
        means "no scope check available" and the check is skipped rather than
        failing closed so non-target hypotheses can still be recorded).
    """
    errors: list[str] = []
    raw_status = (fields.get("status") or "Candidate").strip()
    if raw_status not in CANONICAL_STATES and raw_status not in LEGACY_ALIASES:
        errors.append(
            f"non-canonical status '{raw_status}'; allowed: {', '.join(CANONICAL_STATES)}"
        )
    if fields.get("phase"):
        try:
            normalize_phase(fields["phase"])
        except ValueError:
            errors.append(f"unknown phase '{fields['phase']}'")
    raw_target = (fields.get("target") or "").strip()
    if re.search(r"\s+\(", raw_target):
        errors.append(
            "target must contain only a host/IP/URL; move paths or descriptions to rationale"
        )
    target = normalise_target(raw_target)
    normalised_scope = {normalise_target(host) for host in in_scope_hosts or set()}
    if target and in_scope_hosts is not None and target not in normalised_scope:
        errors.append(
            f"target '{target}' is not in scope; record a hypothesis only for in-scope hosts"
        )
    errors.extend(_validate_rejection_fields(fields))
    return errors


def update_hypothesis(
    path: Path, in_scope_hosts: set[str] | None = None, **fields: Any
) -> Hypothesis:
    """Update a hypothesis in the file by ID (creates if missing).

    Audit P1-hyp: the record is scope/phase validated before any write. If
    validation fails, no file is touched and ``ValueError`` is raised.

    ``in_scope_hosts`` (a host set, or ``None`` to skip the scope check) is
    threaded into ``validate_hypothesis_record`` so an out-of-scope target is
    rejected fail-closed instead of being written to the board.
    """
    normalized_fields = dict(fields)
    normalized_fields["id"] = _normalise_id(fields.get("id"))
    # Build the candidate record so we can validate before mutating the board.
    temp = Hypothesis(
        id=normalized_fields["id"],
        title=normalized_fields.get("title", "") or f"Hypothesis {normalized_fields['id']}",
        status=(normalized_fields.get("status") or "Candidate"),
        phase=(normalized_fields.get("phase") or "").strip(),
        service=(normalized_fields.get("service") or "").strip(),
        port=(normalized_fields.get("port") or "").strip(),
        target=(normalized_fields.get("target") or "").strip(),
        vuln_class=(normalized_fields.get("vuln_class") or "").strip(),
        rationale=(normalized_fields.get("rationale") or "").strip(),
        evidence=(normalized_fields.get("evidence") or "").strip(),
        cve_research=(normalized_fields.get("cve_research") or "").strip(),
        exploit_research=(normalized_fields.get("exploit_research") or "").strip(),
        test_command=(normalized_fields.get("test_command") or "").strip(),
        test_response=(normalized_fields.get("test_response") or "").strip(),
        verification_status=(normalized_fields.get("verification_status") or "").strip(),
        rejection_reason=(normalized_fields.get("rejection_reason") or "").strip(),
        updated=(normalized_fields.get("updated") or "").strip(),
    )
    errors = validate_hypothesis_record(temp.to_dict(), in_scope_hosts=in_scope_hosts)
    if errors:
        raise ValueError("; ".join(errors))

    hypotheses = parse_hypotheses(path)
    h_id = temp.id
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
        target = Hypothesis(id=h_id, title=temp.title)
        hypotheses.append(target)

    # Update fields
    for key, value in normalized_fields.items():
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
    template = path.read_text(encoding="utf-8") if path.exists() else "# Hypothesis Board\n\n"
    # Template instructions are an HTML comment containing an example H-001
    # heading. Remove that comment before locating real records, otherwise a
    # newly written hypothesis is accidentally placed inside the comment.
    comment_start = template.find("<!--")
    if comment_start != -1:
        comment_end = template.find("-->", comment_start)
        if comment_end != -1:
            template = template[:comment_start] + template[comment_end + 3 :]
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
