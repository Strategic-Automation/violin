"""Phase exit gates, methodology gates, coverage matrix, and note redaction."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..core import findings, hypotheses, ptt

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_OPENROUTER_KEY_RE = re.compile(r"\bsk-or-v1-[A-Za-z0-9]+\b")
_CANONICAL_FINDING_OR_HYPOTHESIS_RE = re.compile(r"evidence/|FIND-\d+|H-\d+", re.IGNORECASE)

_EXPECTED_METHODOLOGY_GATES = frozenset(
    {
        "information-gathering",
        "configuration-deployment",
        "authentication-session",
        "authorization",
        "input-validation",
        "error-handling",
        "cryptography",
        "business-logic",
        "client-side",
        "api-testing",
    }
)


def _redact_sensitive_note(note: str) -> str:
    """Prevent credentials and bearer tokens from entering PTT state notes.

    Multiline notes must also be collapsed to a single line: the PTT row table
    format requires a trailing ``|`` on one physical line, and embedded line
    breaks split the row so the row parser drops the task.
    """
    one_line = " ".join(note.splitlines()).strip()
    redacted = _JWT_RE.sub("[REDACTED_JWT]", one_line)
    redacted = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", redacted)
    return _OPENROUTER_KEY_RE.sub("[REDACTED_API_KEY]", redacted)


def _with_skill_token(note: str, skill: str, digest: str) -> str:
    """Keep exactly one replaceable selection token in a PTT note."""
    token = f"[skill:{skill}@{digest}]"
    stripped = re.sub(r"\s*\[skill:[^\]]+\]", "", note).strip()
    return f"{stripped} {token}".strip()


def _validate_disposition_entry(name: str, entry: Any) -> list[str]:
    """Validate a single cell/gate disposition mapping for status and evidence rules."""
    name_normalized = str(name).strip().lower()
    if not isinstance(entry, dict):
        return [f"{name_normalized} (must be a mapping with status and evidence_or_reason)"]
    status = str(entry.get("status") or "").strip().lower()
    reason = str(entry.get("evidence_or_reason") or "").strip()
    if status not in {"tested", "not_applicable", "blocked"} or not reason:
        return [f"{name_normalized} (status in {{tested, not_applicable, blocked}} + reason)"]
    if status == "not_applicable" and "evidence/" not in reason:
        return [f"{name_normalized} (not_applicable without evidence file)"]
    if status == "blocked" and "guard" not in reason.lower():
        return [f"{name_normalized} (blocked without guard reference)"]
    if status == "tested" and not _CANONICAL_FINDING_OR_HYPOTHESIS_RE.search(reason):
        return [f"{name_normalized} (tested without evidence/FIND/hypothesis reference)"]
    return []


def _find_unlinked_validated_hypotheses(
    engagement: Path, board: list[hypotheses.Hypothesis]
) -> list[str]:
    """Return hypothesis IDs for Validated hypotheses lacking a linked canonical findings file."""
    unlinked: list[str] = []
    findings_dir = engagement / "evidence" / "findings"
    for item in board:
        if item.canonical_status() != "Validated":
            continue
        linked_ids = [
            value.strip().upper()
            for value in str(item.linked_findings or "").split(",")
            if value.strip()
        ]
        if not linked_ids or not any(
            (findings_dir / f"{finding_id}.md").is_file() for finding_id in linked_ids
        ):
            unlinked.append(f"H-{item.id}")
    return unlinked


def _validate_phase_exit(engagement: Path, task_id: str, status: str) -> None:
    """Block phase completion while required evidence or dispositions are incomplete."""
    if status != "[x]":
        return
    task = next(
        (item for item in ptt.parse_ptt(engagement / "state" / "ptt.md") if item.id == task_id),
        None,
    )
    if task is None:
        raise ValueError(f"PTT task {task_id!r} is missing")
    phase = ptt.normalize_phase(task.phase)
    board = hypotheses.parse_hypotheses(engagement / "hypotheses.md")

    if phase.value == "VULN_RESEARCH":
        scope_path = engagement / "scope" / "scope.yaml"
        scope_data = (
            yaml.safe_load(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
        )
        if isinstance(scope_data, dict) and (
            (scope_data.get("engagement") or {}).get("audit_mode") is True
        ):
            gates_required = bool(
                (scope_data.get("engagement") or {}).get("require_methodology_gates") is True
            )
            if gates_required:
                _validate_methodology_gates(engagement, scope_data)
            matrix_path = engagement / "state" / "coverage-matrix.yaml"
            if not matrix_path.is_file():
                raise ValueError(
                    "VULN_RESEARCH cannot close until state/coverage-matrix.yaml exists"
                )
            matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
            entries = matrix.get("coverage") if isinstance(matrix, dict) else None
            if not isinstance(entries, dict) or not entries:
                raise ValueError("coverage matrix must contain a non-empty coverage mapping")
            obligations = (scope_data.get("engagement") or {}).get("coverage_obligations") or []
            cell_texts = [
                f"{str(name).lower()} {str(entry.get('evidence_or_reason') or '').lower()}"
                for name, entry in entries.items()
                if isinstance(entry, dict)
            ]
            unresolved_coverage: list[str] = []
            first_missing: str | None = None
            for obligation in obligations:
                obligation_str = str(obligation).strip().lower()
                if not obligation_str:
                    continue
                if not any(obligation_str in text for text in cell_texts):
                    if first_missing is None:
                        first_missing = obligation_str
                    unresolved_coverage.append(f"{obligation_str} (no coverage-matrix cell)")
            for name, entry in entries.items():
                entry_errors = _validate_disposition_entry(name, entry)
                unresolved_coverage.extend(entry_errors)
            if unresolved_coverage:
                hints = [
                    "how to fix: each obligation must map to a coverage-matrix cell",
                    "  - matrix keys are the EXACT lowercased obligation strings from scope.yaml",
                    "    (e.g. 'post /api/v1/auth/login') inside a flat 'coverage:' mapping —",
                    "    no nested 'routes:' block, no slugified keys",
                    "  - 'tested' cells: evidence_or_reason must cite evidence/, FIND-NNN, or a hypothesis id",
                    "  - 'not_applicable' cells: evidence_or_reason must cite an evidence/ file showing the probe",
                    "    (run the probe, save its output under evidence/vuln-research/, then reference that path)",
                    "  - 'blocked' cells: evidence_or_reason must name the guard that prevented testing",
                    "  - minimal valid cell:",
                    "      coverage:",
                    "        'post /api/v1/auth/login':",
                    "          status: tested",
                    "          evidence_or_reason: 'evidence/vuln-research/login.txt HTTP status line'",
                ]
                message = "VULN_RESEARCH cannot close with undispositioned coverage: " + ", ".join(
                    unresolved_coverage
                )
                if first_missing:
                    message += (
                        f". First missing obligation: {first_missing} — add a cell keyed by "
                        "this exact lowercased string"
                    )
                raise ValueError(message + ". " + " ".join(hints))

        unresolved = [
            f"H-{item.id}" for item in board if item.canonical_status() in {"Candidate", "Likely"}
        ]
        if not unresolved:
            untested_disposals: list[str] = []
            for item in board:
                if item.canonical_status() != "Rejected":
                    continue
                if item.verification_status.strip().lower() != "not_implemented":
                    continue
                command = item.test_command.strip().lower()
                evidence_cited = bool((item.runtime_evidence or item.evidence or "").strip())
                if (
                    command in {"", "n/a", "na", "none", "-"}
                    or command.startswith("n/a")
                    or not evidence_cited
                ):
                    untested_disposals.append(
                        f"H-{item.id} (cheapest test: {(item.cheapest_test or '?').strip()!r})"
                    )
            if untested_disposals:
                raise ValueError(
                    "VULN_RESEARCH cannot close with rejections that never ran their "
                    "cheapest discriminating test: "
                    + ", ".join(untested_disposals)
                    + ". Execute the test and record Test Command/Test Response/Runtime "
                    "Evidence (or keep the hypothesis active) before closing."
                )
        if unresolved:
            raise ValueError(
                "VULN_RESEARCH cannot close with unresolved hypotheses: " + ", ".join(unresolved)
            )

        uncanonized = _find_unlinked_validated_hypotheses(engagement, board)
        if uncanonized:
            raise ValueError(
                "VULN_RESEARCH cannot close until every Validated hypothesis links a "
                "canonical findings file: "
                + ", ".join(uncanonized)
                + ". Required format (1:N allowed): a file at exactly "
                "evidence/findings/FIND-NNN.md (NNN = zero-padded numeric id, NO descriptive "
                "suffix/name) whose first line is `# FIND-NNN: <title>`. Update Linked findings "
                "on the hypothesis board via violin_record_hypothesis before closing."
            )

    if phase.value == "REPORTING":
        scope_path = engagement / "scope" / "scope.yaml"
        scope_data = (
            yaml.safe_load(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
        )
        if isinstance(scope_data, dict) and (
            (scope_data.get("engagement") or {}).get("audit_mode") is True
        ):
            history_path = engagement / "state" / "history.md"
            reached_later_phase = False
            if history_path.is_file():
                history_text = history_path.read_text(encoding="utf-8", errors="replace")
                for token in re.findall(r"phase=([a-zA-Z_]+)", history_text):
                    if token.lower() in {"exploitation", "post_exploitation", "privesc", "flags"}:
                        reached_later_phase = True
                        break
            if not reached_later_phase:
                raise ValueError(
                    "REPORTING cannot close: no commands were executed in EXPLOITATION or a "
                    "later phase (all history is phase=recon). "
                    "ROOT CAUSE: PT-103 (EXPLOITATION) was never activated or never ran commands. "
                    "FIX: call violin_record_ptt to set PT-103 status='[~]' (phase=EXPLOITATION), "
                    "then run proof-verification commands under phase=exploitation before closing REPORTING. "
                    "Skipping the exploitation phase produces an incomplete assessment."
                )
        missing = _find_unlinked_validated_hypotheses(engagement, board)
        if missing:
            raise ValueError(
                "REPORTING cannot close until Validated hypotheses link canonical findings: "
                + ", ".join(missing)
            )
        _validate_finding_schemas(engagement)


def _validate_finding_schemas(engagement: Path) -> None:
    """Require every FIND-NNN.md to parse with the canonical schema populated.

    Catches findings written with non-canonical section names (## Summary instead of
    ## Description) or inline evidence, which silently produce empty fields in the
    generated report. Names the exact failing fields per file plus the fix.
    """
    findings_dir = engagement / "evidence" / "findings"
    if not findings_dir.is_dir():
        return
    problems: list[str] = []
    for path in sorted(findings_dir.glob("FIND-*.md")):
        rec = findings.parse_finding_file(path)
        empty = [
            field
            for field in ("severity", "description", "impact", "remediation")
            if not rec.get(field)
        ]
        if not rec.get("evidence") or not all(rec.get("evidence")):
            empty.append("evidence (bullets '- `path`')")
        if not rec.get("hypothesis"):
            empty.append("hypothesis")
        if empty:
            problems.append(f"{path.name}: missing {', '.join(empty)}")
    if problems:
        raise ValueError(
            "REPORTING cannot close with incomplete FIND files: "
            + "; ".join(problems[:5])
            + ". Canonical schema: first line '# FIND-NNN: <title>'; top-level bullet "
            "'- **Severity:** value'; section heads exactly '## Description', "
            "'## Impact', '## Evidence', '## Remediation'; evidence bullets "
            "'- `evidence/...`'. Rewrite the file(s) to that schema and retry."
        )


def _validate_methodology_gates(engagement: Path, scope_data: dict[str, Any]) -> None:
    """Require a dispositioned methodology-gates file before VULN_RESEARCH closes."""
    expected_gates = _EXPECTED_METHODOLOGY_GATES
    gates_path = engagement / "state" / "methodology-gates.yaml"
    if not gates_path.is_file():
        raise ValueError(
            "VULN_RESEARCH cannot close until state/methodology-gates.yaml exists "
            "(disposition each WSTG category: tested / not_applicable / blocked with evidence). "
            "Minimal valid file:\n"
            "  gates:\n"
            "    authentication-session:\n"
            "      status: tested\n"
            "      evidence_or_reason: 'evidence/vuln-research/login.txt' (e.g. no lockout,\n"
            "        no 429 after N rapid attempts if claiming a rate-limit finding)\n"
            "    client-side:\n"
            "      status: not_applicable\n"
            "      evidence_or_reason: 'evidence/vuln-research/redirect-probe.txt' shows\n"
            "        no unvalidated redirect sink\n"
            "    business-logic:\n"
            "      status: blocked\n"
            "      evidence_or_reason: 'guard blocked referral param enumeration out of scope'\n"
        )
    gates = yaml.safe_load(gates_path.read_text(encoding="utf-8"))
    entries = gates.get("gates") if isinstance(gates, dict) else None
    if not isinstance(entries, dict) or not entries:
        raise ValueError("methodology gates must contain a non-empty 'gates:' mapping")

    missing_gates = expected_gates - {str(key).strip().lower() for key in entries}
    if missing_gates:
        raise ValueError(
            "VULN_RESEARCH cannot close with undispositioned methodology gates: "
            + ", ".join(sorted(missing_gates))
            + ". Add each category under a flat 'gates:' mapping (e.g. "
            "'authentication-session:') with status and evidence_or_reason."
        )

    unresolved: list[str] = []
    for name, entry in entries.items():
        unresolved.extend(_validate_disposition_entry(name, entry))
    if unresolved:
        raise ValueError(
            "VULN_RESEARCH cannot close with unresolved methodology gates: "
            + ", ".join(unresolved)
            + ". Each gate: status tested/not_applicable/blocked; not_applicable cites an "
            "evidence file; blocked names the guard; tested cites evidence/, FIND-NNN, or H-NNN."
        )


__all__ = [
    "_find_unlinked_validated_hypotheses",
    "_redact_sensitive_note",
    "_validate_disposition_entry",
    "_validate_methodology_gates",
    "_validate_phase_exit",
    "_with_skill_token",
]
