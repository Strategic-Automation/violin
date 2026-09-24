"""Pure disposition and obligation rules shared by gates and scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_CANONICAL_EVIDENCE_REFERENCE = re.compile(r"evidence/|FIND-\d+|H-\d+", re.IGNORECASE)
EXPECTED_METHODOLOGY_GATES = frozenset(
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


@dataclass(frozen=True)
class DispositionEvaluation:
    """The policy result for a disposition mapping, without filesystem concerns."""

    entry_errors: tuple[str, ...]
    missing_obligations: tuple[str, ...]
    unrecognized_entries: tuple[str, ...]
    missing_required_names: tuple[str, ...]
    completed: int
    total: int

    @property
    def complete(self) -> bool:
        return bool(self.total) and not (
            self.entry_errors
            or self.missing_obligations
            or self.unrecognized_entries
            or self.missing_required_names
        )


def disposition_entry_errors(name: str, entry: Any) -> tuple[str, ...]:
    """Return the domain violations for one coverage or methodology disposition."""

    normalized_name = str(name).strip().lower()
    if not isinstance(entry, dict):
        return (f"{normalized_name} (must be a mapping with status and evidence_or_reason)",)

    status = str(entry.get("status") or "").strip().lower()
    reason = str(entry.get("evidence_or_reason") or "").strip()
    if status not in {"tested", "not_applicable", "blocked"} or not reason:
        return (f"{normalized_name} (status in {{tested, not_applicable, blocked}} + reason)",)
    if status == "not_applicable" and "evidence/" not in reason:
        return (f"{normalized_name} (not_applicable without evidence file)",)
    if status == "blocked" and "guard" not in reason.lower():
        return (f"{normalized_name} (blocked without guard reference)",)
    if status == "tested" and not _CANONICAL_EVIDENCE_REFERENCE.search(reason):
        return (f"{normalized_name} (tested without evidence/FIND/hypothesis reference)",)
    return ()


def evaluate_dispositions(
    entries: Any,
    *,
    obligations: list[Any] | tuple[Any, ...] = (),
    required_names: set[str] | frozenset[str] = frozenset(),
) -> DispositionEvaluation:
    """Evaluate a flat disposition mapping against its applicable domain rules.

    Obligation matching intentionally follows the established close-gate contract:
    each lowercased obligation may appear in either a cell key or its evidence text,
    and every cell must refer to at least one declared obligation.
    """

    if not isinstance(entries, dict):
        return DispositionEvaluation(
            entry_errors=(),
            missing_obligations=tuple(
                str(item).strip().lower() for item in obligations if str(item).strip()
            ),
            unrecognized_entries=(),
            missing_required_names=tuple(sorted(name.strip().lower() for name in required_names)),
            completed=0,
            total=0,
        )

    normalized_obligations = tuple(
        dict.fromkeys(str(item).strip().lower() for item in obligations if str(item).strip())
    )
    normalized_required = {
        str(name).strip().lower() for name in required_names if str(name).strip()
    }
    normalized_names = {str(name).strip().lower() for name in entries}
    missing_required_names = tuple(sorted(normalized_required - normalized_names))

    entry_errors: list[str] = []
    unrecognized_entries: list[str] = []
    invalid_entries: set[str] = set()
    valid_cells: list[tuple[str, str]] = []
    for name, entry in entries.items():
        normalized_name = str(name).strip().lower()
        reason = (
            str(entry.get("evidence_or_reason") or "").strip().lower()
            if isinstance(entry, dict)
            else ""
        )
        cell_text = f"{normalized_name} {reason}"
        cell_errors = disposition_entry_errors(name, entry)
        entry_errors.extend(cell_errors)
        if cell_errors:
            invalid_entries.add(normalized_name)
        if normalized_obligations and not any(
            obligation in cell_text for obligation in normalized_obligations
        ):
            unrecognized_entries.append(
                f"{name} (unrecognised obligation key; accepted keys: "
                f"{', '.join(sorted(normalized_obligations))})"
            )
            invalid_entries.add(normalized_name)
        if not cell_errors:
            valid_cells.append((cell_text, normalized_name))

    missing_obligations = tuple(
        obligation
        for obligation in normalized_obligations
        if not any(obligation in cell_text for cell_text, _ in valid_cells)
    )
    valid_names = {name for _, name in valid_cells}
    if normalized_obligations:
        completed = sum(
            any(obligation in cell_text for cell_text, _ in valid_cells)
            for obligation in normalized_obligations
        )
        total = len(normalized_obligations) + len(invalid_entries)
    else:
        valid_count = sum(
            not disposition_entry_errors(name, entry) for name, entry in entries.items()
        )
        if normalized_required:
            completed = sum(name in valid_names for name in normalized_required) + sum(
                name not in normalized_required and name in valid_names for name in normalized_names
            )
            total = len(normalized_required) + len(normalized_names - normalized_required)
        else:
            completed = valid_count
            total = len(entries)

    return DispositionEvaluation(
        entry_errors=tuple(entry_errors),
        missing_obligations=missing_obligations,
        unrecognized_entries=tuple(unrecognized_entries),
        missing_required_names=missing_required_names,
        completed=completed,
        total=total,
    )
