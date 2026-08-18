"""Hypothesis board parsing, validation, and mutation.

Canonical states: Candidate, Likely, Validated, Rejected.
Legacy aliases: Researching->Candidate, Verified->Validated.

Records are scope/phase bound: a hypothesis must carry a canonical status, a
valid phase, and a target that is in scope (audit P1-hyp).
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .phases import normalize_phase
from .state import atomic_text, ensure_dir
from .targets import normalize_target

__all__ = [
    "Hypothesis",
    "parse_hypotheses",
    "update_hypothesis",
    "validate_hypothesis_record",
]

# Canonical states
CANONICAL_STATES = ("Candidate", "Likely", "Validated", "Rejected")
LEGACY_ALIASES = {
    "Researching": "Candidate",
    "Verified": "Validated",
}

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
    "linked findings": "linked_findings",
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
    linked_findings: str = ""
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
        if self.linked_findings:
            lines.append(f"- **Linked findings:** {self.linked_findings}")
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


def _normalize_status(status: str) -> str:
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


def _normalize_id(value: Any) -> str:
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
    line = line.lstrip("- ").strip()
    # Accept ### H-001, ## H-001, # H-001, or bare H-001. A hypothesis row can
    # legitimately sit under a single-## or double-## subheading (e.g. grouped by
    # vuln class), so requiring exactly "### " is too fragile — it silently drops
    # every row written at another heading depth, which reads as "untested".
    stripped = line.lstrip("#").strip()
    if not stripped.startswith("H-"):
        # tolerate "H-001" without a dash-space after run of (non-empty) hashes
        if not line.startswith("H-"):
            return None
        stripped = line
    identifier, separator, title = stripped.removeprefix("H-").partition(":")
    if not separator or not identifier.strip().isdigit() or not title.strip():
        return None
    return Hypothesis(id=identifier.strip(), title=title.strip())


def _apply_field(hypothesis: Hypothesis, line: str) -> None:
    line = line.removeprefix("- ").strip()
    if line.startswith("**"):
        line = line.removeprefix("**")
    if not line:
        return
    label, separator, value = line.partition(":")
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


def validate_hypothesis_record(
    fields: dict[str, Any],
    in_scope_hosts: set[str] | None = None,
    engagement_dir: Path | None = None,
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
    target = normalize_target(raw_target)
    normalized_scope = {normalize_target(host) for host in in_scope_hosts or set()}
    in_scope = target in normalized_scope or any(
        host.startswith("*.") and target.endswith(host[1:]) and target != host[2:]
        for host in normalized_scope
    )
    if target and in_scope_hosts is not None and not in_scope:
        errors.append(
            f"target '{target}' is not in scope; record a hypothesis only for in-scope hosts"
        )
    errors.extend(_validate_rejection_fields(fields))
    if _normalize_status(str(fields.get("status") or "Candidate")) == "Validated":
        raw_evidence = str(fields.get("runtime_evidence") or "").strip()
        if not raw_evidence:
            errors.append(
                "status='Validated' requires the 'runtime_evidence' field (e.g. "
                "'evidence/executions/001-command.json' or 'evidence/exploitation/poc.txt'); "
                "source evidence alone is not proof"
            )
        elif engagement_dir is not None:
            evidence_root = (engagement_dir / "evidence").resolve()
            evidence_paths = [part.strip() for part in raw_evidence.split(",") if part.strip()]
            if not evidence_paths:
                errors.append(f"runtime_evidence must not be empty: {raw_evidence}")
            for raw_path in evidence_paths:
                relative = Path(raw_path)
                candidate = (
                    (engagement_dir / relative).resolve()
                    if not relative.is_absolute()
                    else relative.resolve()
                )
                if relative.is_absolute() or not candidate.is_relative_to(evidence_root):
                    errors.append(
                        "runtime_evidence must be an engagement-relative path beneath "
                        f"evidence/ (got: {raw_path})"
                    )
                elif relative.is_symlink() or not candidate.is_file():
                    errors.append(
                        f"runtime_evidence does not name an existing regular file: {raw_path}"
                    )
                elif candidate.stat().st_size == 0:
                    errors.append(f"runtime_evidence must not be empty: {raw_path}")
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
    hypotheses_list = parse_hypotheses(path)
    ids = [hypothesis.id for hypothesis in hypotheses_list]
    duplicate_ids = sorted({identifier for identifier in ids if ids.count(identifier) > 1})
    if duplicate_ids:
        raise ValueError(
            "hypotheses.md contains duplicate IDs; repair the board before updating: "
            + ", ".join(f"H-{identifier}" for identifier in duplicate_ids)
        )
    supplied_id = fields.get("id")
    if supplied_id:
        normalized_fields["id"] = _normalize_id(supplied_id)
    else:
        numeric_ids = [int(hyp.id) for hyp in hypotheses_list if hyp.id.isdigit()]
        normalized_fields["id"] = str(max(numeric_ids, default=0) + 1).zfill(3)

    h_id = normalized_fields["id"]
    existing = next((hyp for hyp in hypotheses_list if hyp.id == h_id), None)
    existing_dict = existing.to_dict() if existing else {}
    merged_fields = {**existing_dict, **normalized_fields}

    # Build the candidate record so we can validate before mutating the board.
    valid_fields = {field_obj.name for field_obj in dataclasses.fields(Hypothesis)}
    init_kwargs = {
        field_key: (field_val.strip() if isinstance(field_val, str) else field_val)
        for field_key, field_val in merged_fields.items()
        if field_key in valid_fields
    }
    if not init_kwargs.get("title"):
        init_kwargs["title"] = f"Hypothesis {init_kwargs.get('id', '')}"
    if not init_kwargs.get("status"):
        init_kwargs["status"] = "Candidate"
    temp = Hypothesis(**init_kwargs)
    errors = validate_hypothesis_record(
        temp.to_dict(), in_scope_hosts=in_scope_hosts, engagement_dir=path.resolve().parent
    )
    if errors:
        raise ValueError("; ".join(errors))

    h_id = temp.id
    if not h_id:
        raise ValueError("id is required")

    # Find existing
    target = None
    for hypothesis in hypotheses_list:
        if hypothesis.id == h_id:
            target = hypothesis
            break

    if target is None:
        # Create new
        target = Hypothesis(id=h_id, title=temp.title)
        hypotheses_list.append(target)

    # Update fields
    for key, value in normalized_fields.items():
        if key == "id":
            continue
        if hasattr(target, key):
            setattr(target, key, value)

    # Always update timestamp
    target.updated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")

    original = path.read_text(encoding="utf-8") if path.exists() else ""

    # Rewrite file, then verify the requested canonical ID was the sole record
    # changed. A malformed board must fail closed rather than silently merging
    # a new record into a neighbouring hypothesis.
    _rewrite_hypotheses(path, hypotheses_list)
    persisted = [hypothesis for hypothesis in parse_hypotheses(path) if hypothesis.id == h_id]
    if len(persisted) != 1 or persisted[0].title != target.title:
        atomic_text(path, original)
        raise ValueError(
            f"hypothesis update integrity check failed for H-{h_id}; original board was restored"
        )
    return target


def _rewrite_hypotheses(path: Path, hypotheses_list: list[Hypothesis]) -> None:
    """Rewrite the hypotheses file while preserving structural sections (Decoy Trail, Observations, etc.)."""
    ensure_dir(path.parent)
    template = path.read_text(encoding="utf-8") if path.exists() else "# Hypothesis Board\n\n"

    # Remove template instruction HTML comment if present
    template = re.sub(r"<!--.*?-->", "", template, flags=re.DOTALL)

    # Preserve section structure (e.g. ## Active Theories ... ## Observations ... ## Decoy Trail)
    active_heading = "## Active Theories"
    active_pos = template.find(active_heading)

    if active_pos != -1:
        header = template[: active_pos + len(active_heading)].strip() + "\n\n"
        # Find next section header after Active Theories
        next_sec = re.search(r"\n##\s+(?!Active Theories)", template[active_pos:])
        trailer = template[active_pos + next_sec.start() + 1 :].lstrip() if next_sec else ""
    else:
        # Fallback: locate first hypothesis heading starting with ### H-
        first_heading = re.search(r"^###\s+H-", template, re.MULTILINE)
        if first_heading:
            header = template[: first_heading.start()].rstrip() + "\n\n"
            next_sec = re.search(r"\n##\s+", template[first_heading.start() :])
            trailer = (
                template[first_heading.start() + next_sec.start() + 1 :].lstrip()
                if next_sec
                else ""
            )
        else:
            header = template.strip() + "\n\n"
            trailer = ""

    body = "\n".join(hypothesis.to_markdown() for hypothesis in hypotheses_list)
    content = header + body + ("\n\n" + trailer if trailer else "\n")
    atomic_text(path, content)
