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

from plugins.violin_guard.core.commands.targets import normalize_target
from plugins.violin_guard.core.engagement.markdown_structure import (
    MarkdownBlock,
    iter_markdown_blocks,
    read_markdown,
)
from plugins.violin_guard.core.engagement.phases import normalize_phase
from plugins.violin_guard.core.engagement.state import atomic_text, ensure_dir

__all__ = [
    "Hypothesis",
    "find_by_id",
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


def find_by_id(path: Path, hypothesis_id: str) -> Hypothesis | None:
    """Return the hypothesis addressed by ``H-007`` or ``007``, else ``None``.

    Deliberately tolerant: a stale or malformed id recorded in a binding must
    fall back to the caller's default rather than raise mid-resolution.
    """

    try:
        normalized = _normalize_id(hypothesis_id)
    except ValueError:
        return None
    if not normalized:
        return None
    return next((item for item in parse_hypotheses(path) if item.id == normalized), None)


def parse_hypotheses(path: Path) -> list[Hypothesis]:
    """Parse canonical hypothesis records from the Active Theories section."""
    if not path.exists():
        return []
    return [record for record, _start, _end in _hypothesis_record_spans(read_markdown(path))[1]]


_HYPOTHESIS_HEADING = re.compile(r"^H-(?P<id>\d+):\s*(?P<title>.+?)\s*$")
_HYPOTHESIS_SECTION = "active theories"


def _parse_heading_text(heading: MarkdownBlock) -> Hypothesis | None:
    if heading.level != 3:
        return None
    match = _HYPOTHESIS_HEADING.fullmatch(heading.text.strip())
    if not match:
        return None
    return Hypothesis(id=match.group("id"), title=match.group("title"))


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

    original = read_markdown(path) if path.exists() else ""

    # Rewrite file, then verify the requested canonical ID was the sole record
    # changed. A malformed board must fail closed rather than silently merging
    # a new record into a neighbouring hypothesis.
    _rewrite_hypotheses(path, hypotheses_list)
    persisted = [hypothesis for hypothesis in parse_hypotheses(path) if hypothesis.id == h_id]
    if len(persisted) != 1 or persisted[0].title != target.title:
        atomic_text(path, original)
        raise ValueError(
            f"hypothesis update integrity check failed for H-{h_id}; original board was "
            "restored. The record did not persist as a single block — inspect the board's "
            "hypothesis headings and HTML comments, then retry once they are consistent."
        )
    return target


def _hypothesis_record_spans(
    source: str,
) -> tuple[tuple[int, int] | None, list[tuple[Hypothesis, int, int]]]:
    blocks = list(iter_markdown_blocks(source))
    headings = [block for block in blocks if block.kind == "heading"]
    protected = [(block.start, block.end) for block in blocks if block.kind == "protected"]
    lines = source.splitlines()
    sections = [
        heading
        for heading in headings
        if heading.level == 2 and heading.text.casefold() == _HYPOTHESIS_SECTION
    ]
    if len(sections) > 1:
        raise ValueError("hypotheses.md must contain exactly one ## Active Theories section")
    if not sections:
        return None, []
    section_heading = sections[0]
    section_start = section_heading.end
    section_end = next(
        (
            heading.start
            for heading in headings
            if heading.start > section_heading.start and heading.level <= 2
        ),
        len(lines),
    )
    headings = [
        heading
        for heading in headings
        if section_start <= heading.start < section_end and heading.level > 2
    ]
    records: list[tuple[Hypothesis, int, int]] = []
    for index, heading in enumerate(headings):
        record = _parse_heading_text(heading)
        if record is None:
            if heading.text.strip().startswith("H-"):
                raise ValueError(
                    f"invalid hypothesis heading on line {heading.start + 1}; "
                    "expected ### H-<number>: <title> inside ## Active Theories"
                )
            continue
        record_end = next(
            (
                boundary.start
                for boundary in headings[index + 1 :]
                if boundary.level <= heading.level
            ),
            section_end,
        )
        for line_index in range(heading.end, record_end):
            if line_index < len(lines) and not any(
                start <= line_index < end for start, end in protected
            ):
                _apply_field(record, lines[line_index].strip())
        records.append((record, heading.start, record_end))
    return (section_start, section_end), records


def _rewrite_hypotheses(path: Path, hypotheses_list: list[Hypothesis]) -> None:
    """Splice canonical record blocks while preserving all surrounding source text."""
    ensure_dir(path.parent)
    source = read_markdown(path) if path.exists() else "# Hypothesis Board\n\n"
    newline = "\r\n" if "\r\n" in source else "\n"
    section, existing = _hypothesis_record_spans(source)
    requested: dict[str, Hypothesis] = {}
    for hypothesis in hypotheses_list:
        if hypothesis.id in requested:
            raise ValueError(f"duplicate hypothesis id: H-{hypothesis.id}")
        requested[hypothesis.id] = hypothesis

    lines = source.splitlines(keepends=True)
    if section is None:
        if not hypotheses_list:
            atomic_text(path, source)
            return
        suffix = "" if not source else ("" if source.endswith(("\n", "\r")) else newline)
        if source and not source.endswith((newline + newline,)):
            suffix += newline
        if source and not source.endswith((newline + newline,)):
            suffix += newline
        rendered = "".join(
            hypothesis.to_markdown().replace("\n", newline) + newline
            for hypothesis in hypotheses_list
        )
        atomic_text(path, source + suffix + "## Active Theories" + newline + newline + rendered)
        return

    _section_start, section_end = section
    edits: list[tuple[int, int, str]] = []
    emitted: set[str] = set()
    for record, start, end in existing:
        replacement = ""
        updated = requested.get(record.id)
        if updated is not None and record.id not in emitted:
            replacement = updated.to_markdown().replace("\n", newline)
            emitted.add(record.id)
        # Preserve blank lines and separators owned by the document rather than the
        # record so changing a record does not normalize its neighboring sections.
        content_end = end
        while content_end > start and not lines[content_end - 1].strip():
            content_end -= 1
        edits.append((start, content_end, replacement))

    pending = "".join(
        requested[identifier].to_markdown().replace("\n", newline)
        for identifier in requested
        if identifier not in emitted
    )
    if pending:
        # Keep the source's existing blank space before the next section intact.
        prefix = "".join(lines[:section_end])
        if prefix and not prefix.endswith(("\n", "\r")):
            pending = newline + newline + pending
        elif prefix and not prefix.endswith(newline + newline):
            pending = newline + pending
        edits.append((section_end, section_end, pending))

    output: list[str] = []
    cursor = 0
    for start, end, replacement in sorted(edits, key=lambda edit: (edit[0], edit[1])):
        output.extend(lines[cursor:start])
        output.append(replacement)
        cursor = end
    output.extend(lines[cursor:])
    atomic_text(path, "".join(output))
