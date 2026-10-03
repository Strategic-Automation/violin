"""Canonical hypothesis records, identifiers, and Markdown fields."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

# Canonical states
CANONICAL_STATES = ("Candidate", "Likely", "Validated", "Rejected")
LEGACY_ALIASES = {
    "Researching": "Candidate",
    "Verified": "Validated",
}

FIELD_NAMES = {
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
    "candidate source": "candidate_source",
    "entry point": "entry_point",
    "data flow": "data_flow",
    "source evidence": "source_evidence",
    "runtime evidence": "runtime_evidence",
    "updated": "updated",
    "confidence": "confidence",
    "timebox": "timebox",
    "cheapest test": "cheapest_test",
    "kill criteria": "kill_criteria",
    "next step": "next_step",
}


@dataclass
class Hypothesis:
    id: str
    title: str
    status: str = "Candidate"
    confidence: str = ""
    timebox: str = ""
    cheapest_test: str = ""
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
    kill_criteria: str = ""
    rejection_reason: str = ""
    next_step: str = ""
    candidate_source: str = ""
    entry_point: str = ""
    data_flow: str = ""
    source_evidence: str = ""
    runtime_evidence: str = ""
    updated: str = ""

    def canonical_status(self) -> str:
        return LEGACY_ALIASES.get(self.status, self.status)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.canonical_status()
        return data

    def to_markdown(self) -> str:
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        lines = [f"### H-{self.id}: {self.title}"]
        lines.append(f"- **Status:** {self.canonical_status()}")
        if self.confidence:
            lines.append(f"- **Confidence:** {self.confidence}")
        if self.timebox:
            lines.append(f"- **Timebox:** {self.timebox}")
        if self.cheapest_test:
            lines.append(f"- **Cheapest test:** {self.cheapest_test}")
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
        if self.kill_criteria:
            lines.append(f"- **Kill criteria:** {self.kill_criteria}")
        if self.rejection_reason:
            lines.append(f"- **Rejection Reason:** {self.rejection_reason}")
        if self.next_step:
            lines.append(f"- **Next step:** {self.next_step}")
        for label, value in (
            ("Candidate Source", self.candidate_source),
            ("Entry Point", self.entry_point),
            ("Data Flow", self.data_flow),
            ("Source Evidence", self.source_evidence),
            ("Runtime Evidence", self.runtime_evidence),
        ):
            if value:
                lines.append(f"- **{label}:** {value}")
        lines.append(f"- **Updated:** {self.updated or now}")
        return "\n".join(lines) + "\n"


def normalize_hypothesis_status(status: str) -> str:
    """Normalize a status token, tolerating a trailing confidence/source suffix.

    Agents legitimately write "Validated (conf 0.9)" or "Validated (stored raw;
    render context confirmed)". Canonical matching must key on the leading state
    token so those rows still read as Validated/Rejected/Candidate/Likely.
    """
    value = status.strip()
    # Cut any parenthetical annotation: "Validated (conf 0.9)" -> "Validated".
    head = value.split("(", 1)[0].strip()
    if head:
        value = head
    return LEGACY_ALIASES.get(value, value)


def normalize_hypothesis_id(value: Any) -> str:
    """Accept user-facing H-001 forms but persist the canonical numeric ID."""

    normalized = str(value or "").strip()
    while normalized.upper().startswith("H-"):
        normalized = normalized[2:].strip()
    if not normalized:
        return ""
    if not normalized.isdigit():
        raise ValueError(
            "hypothesis id must be numeric or in the form H-001 (e.g. H-100, 100); "
            "use the next free H-NNN for new hypotheses"
        )
    return normalized.zfill(3)
