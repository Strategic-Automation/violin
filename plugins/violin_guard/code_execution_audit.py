"""Audit contract for Hermes' arbitrary ``execute_code`` tool.

``execute_code`` can run arbitrary Python outside Violin's typed executor.  It
therefore remains available only with explicit engagement metadata and produces
an engagement-local source receipt plus a command-history record.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import command, history, state

_HEADER = re.compile(r"^\s*#\s*violin:\s*(\{.*\})\s*$")
_REQUIRED_FIELDS = frozenset({"eng_dir", "phase", "target", "session_id"})


def parse_metadata(source: object) -> tuple[dict[str, str] | None, str | None]:
    """Parse the required first-line Violin JSON header from Python source."""
    if not isinstance(source, str) or not source.strip():
        return None, "execute_code requires a non-empty `code` string"
    first_line = source.splitlines()[0] if source.splitlines() else ""
    match = _HEADER.fullmatch(first_line)
    if not match:
        return None, (
            "execute_code requires first-line metadata: "
            '# violin: {"eng_dir":"...","phase":"...","target":"...","session_id":"..."}'
        )
    try:
        raw = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        return None, f"execute_code metadata must be valid JSON: {exc.msg}"
    if not isinstance(raw, dict) or set(raw) != _REQUIRED_FIELDS:
        return (
            None,
            "execute_code metadata must contain exactly eng_dir, phase, target, and session_id",
        )
    if not all(isinstance(raw[name], str) and raw[name].strip() for name in _REQUIRED_FIELDS):
        return None, "execute_code metadata values must be non-empty strings"
    return {name: raw[name].strip() for name in _REQUIRED_FIELDS}, None


def validate_source(source: object) -> tuple[dict[str, str] | None, str | None]:
    """Validate metadata against the same engagement gates as command execution."""
    metadata, error = parse_metadata(source)
    if error or metadata is None:
        return None, error
    eng_dir = state.resolve_eng_dir(metadata["eng_dir"])
    gate = command.check_command(
        command.CheckCommandArgs(
            command=f"execute_code sha256={source_digest(source)}",
            phase=metadata["phase"],
            eng_dir=str(eng_dir),
            scope=str(eng_dir / "scope" / "scope.yaml"),
            target=metadata["target"],
            session_id=metadata["session_id"],
        )
    )
    if gate.errors:
        return None, "execute_code blocked by Violin guard: " + "; ".join(gate.errors)
    return metadata, None


def source_digest(source: object) -> str:
    return hashlib.sha256(str(source).encode("utf-8")).hexdigest()


def record_completion(source: object, result: object, duration_ms: object = 0) -> Path | None:
    """Persist source and completion metadata, then append one history record."""
    metadata, error = parse_metadata(source)
    if error or metadata is None:
        return None
    eng_dir = state.resolve_eng_dir(metadata["eng_dir"])
    digest = source_digest(source)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    phase_dir = metadata["phase"].lower().replace("_", "-")
    receipt = eng_dir / "evidence" / phase_dir / f"execute-code-{stamp}-{digest[:12]}.py"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(str(source), encoding="utf-8")

    summary = _result_summary(result, duration_ms)
    command_text = (
        f"execute_code sha256={digest} target={metadata['target']} "
        f"duration_ms={summary['duration_ms']} status={summary['status']}"
    )
    history.append_history(
        eng_dir,
        command_text,
        metadata["phase"],
        summary["exit_code"],
        str(receipt),
    )
    return receipt


def _result_summary(result: object, duration_ms: object) -> dict[str, int | str]:
    try:
        parsed: Any = json.loads(result) if isinstance(result, str) else result
    except json.JSONDecodeError:
        parsed = {"error": "non-JSON tool result"}
    failed = isinstance(parsed, dict) and bool(parsed.get("error"))
    try:
        elapsed = max(0, int(duration_ms))
    except (TypeError, ValueError):
        elapsed = 0
    return {"status": "error" if failed else "ok", "exit_code": int(failed), "duration_ms": elapsed}


__all__ = ["parse_metadata", "record_completion", "source_digest", "validate_source"]
