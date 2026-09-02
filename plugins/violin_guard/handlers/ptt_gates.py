"""Phase exit gates, methodology gates, coverage matrix, and note redaction."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..core import hypotheses, ptt

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
        close_errors: list[str] = []
        if isinstance(scope_data, dict) and (
            (scope_data.get("engagement") or {}).get("audit_mode") is True
        ):
            gates_required = bool(
                (scope_data.get("engagement") or {}).get("require_methodology_gates") is True
            )
            if gates_required:
                close_errors.extend(_methodology_gate_errors(engagement, scope_data))
            matrix_path = engagement / "state" / "coverage-matrix.yaml"
            if not matrix_path.is_file():
                close_errors.append(
                    "VULN_RESEARCH cannot close until state/coverage-matrix.yaml exists"
                )
            else:
                matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
                entries = matrix.get("coverage") if isinstance(matrix, dict) else None
                if not isinstance(entries, dict) or not entries:
                    close_errors.append("coverage matrix must contain a non-empty coverage mapping")
                else:
                    obligations = (scope_data.get("engagement") or {}).get(
                        "coverage_obligations"
                    ) or []
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
                            unresolved_coverage.append(
                                f"{obligation_str} (no coverage-matrix cell)"
                            )
                    for name, entry in entries.items():
                        unresolved_coverage.extend(_validate_disposition_entry(name, entry))
                    if unresolved_coverage:
                        hints = [
                            "how to fix: each obligation must map to a coverage-matrix cell",
                            "  - matrix keys are the EXACT lowercased obligation strings from scope.yaml",
                            "    (e.g. 'post /api/v1/auth/login') inside a flat 'coverage:' mapping —",
                            "    no nested 'routes:' block, no slugified keys",
                            "  - 'tested' cells: evidence_or_reason must cite evidence/ or a hypothesis id",
                            "  - 'not_applicable' cells: evidence_or_reason must cite an evidence/ file showing the probe",
                            "    (run the probe, save its output under evidence/vuln-research/, then reference that path)",
                            "  - 'blocked' cells: evidence_or_reason must name the guard that prevented testing",
                            "  - minimal valid cell:",
                            "      coverage:",
                            "        'post /api/v1/auth/login':",
                            "          status: tested",
                            "          evidence_or_reason: 'evidence/vuln-research/login.txt HTTP status line'",
                        ]
                        message = "undispositioned coverage: " + ", ".join(unresolved_coverage)
                        if first_missing:
                            message += (
                                f". First missing obligation: {first_missing} — add a cell keyed by "
                                "this exact lowercased string"
                            )
                        close_errors.append(message + ". " + " ".join(hints))

        unresolved = [
            f"H-{item.id}" for item in board if item.canonical_status() in {"Candidate", "Likely"}
        ]
        if unresolved:
            close_errors.append("unresolved hypotheses: " + ", ".join(unresolved))
        else:
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
                close_errors.append(
                    "rejections that never ran their cheapest discriminating test: "
                    + ", ".join(untested_disposals)
                    + ". Execute the test and record Test Command/Test Response/Runtime "
                    "Evidence (or keep the hypothesis active) before closing."
                )

        if close_errors:
            raise ValueError(
                "VULN_RESEARCH cannot close — fix ALL of the following (they are listed "
                "together so you can resolve them in one pass):\n  - " + "\n  - ".join(close_errors)
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
                    "then run proof-capture commands (re-run the exploit to save its decisive "
                    "output as evidence) under phase=exploitation before closing REPORTING. "
                    "Skipping the exploitation phase produces an incomplete assessment."
                )


def _methodology_gate_errors(engagement: Path, scope_data: dict[str, Any]) -> list[str]:
    """Return every methodology-gate close failure as a list (empty = pass).

    Refactored from _validate_methodology_gates so the phase-exit gate can
    surface ALL missing preconditions in one error instead of one at a time.
    """
    expected_gates = _EXPECTED_METHODOLOGY_GATES
    gates_path = engagement / "state" / "methodology-gates.yaml"
    if not gates_path.is_file():
        return [
            "state/methodology-gates.yaml exists (disposition each WSTG category: "
            "tested / not_applicable / blocked with evidence). Minimal valid file:\n"
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
            "      evidence_or_reason: 'guard blocked referral param enumeration out of scope'"
        ]
    gates = yaml.safe_load(gates_path.read_text(encoding="utf-8"))
    entries = gates.get("gates") if isinstance(gates, dict) else None
    if not isinstance(entries, dict) or not entries:
        return ["methodology gates must contain a non-empty 'gates:' mapping"]

    errors: list[str] = []
    missing_gates = expected_gates - {str(key).strip().lower() for key in entries}
    if missing_gates:
        errors.append(
            "undispositioned methodology gates: "
            + ", ".join(sorted(missing_gates))
            + ". Add each category under a flat 'gates:' mapping (e.g. "
            "'authentication-session:') with status and evidence_or_reason."
        )
    for name, entry in entries.items():
        errors.extend(_validate_disposition_entry(name, entry))
    return errors


def _validate_methodology_gates(engagement: Path, scope_data: dict[str, Any]) -> None:
    """Require a dispositioned methodology-gates file before VULN_RESEARCH closes."""
    errors = _methodology_gate_errors(engagement, scope_data)
    if errors:
        raise ValueError(
            "VULN_RESEARCH cannot close with unresolved methodology gates: " + "; ".join(errors)
        )


__all__ = [
    "_redact_sensitive_note",
    "_validate_disposition_entry",
    "_validate_methodology_gates",
    "_validate_phase_exit",
    "_with_skill_token",
]
