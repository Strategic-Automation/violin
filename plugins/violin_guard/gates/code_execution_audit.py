"""Audit contract for Hermes' arbitrary ``execute_code`` tool.

``execute_code`` can run arbitrary Python outside Violin's typed executor.  It
therefore remains available only with explicit engagement metadata and produces
an engagement-local source receipt plus a command-history record.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core import history, state
from ..core.ptt import find_active_task, parse_ptt
from ..core.targets import extract_target_candidates, normalize_target
from ..engine.execution import _commit_guard_state
from . import command

_HEADER = re.compile(r"^\s*#\s*violin:\s*(\{.*\})\s*$")
_REQUIRED_FIELDS = frozenset({"eng_dir", "phase", "target", "session_id"})

_LOCAL_PATH_EXTENSIONS = frozenset(
    {
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".txt",
        ".log",
        ".py",
        ".sh",
        ".env",
        ".csv",
        ".xml",
        ".html",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".wav",
        ".mp3",
        ".zip",
        ".tar",
        ".gz",
        ".tokens.env",
    }
)
_LOCAL_PATH_RE = re.compile(r"(?i)FIND-\d+\.md|evidence/|state/|scope/|\./|\.\./|/tmp/|\.creds/")
_LOCAL_ANALYSIS_IMPORTS = frozenset(
    {
        "ast",
        "base64",
        "binascii",
        "collections",
        "csv",
        "dataclasses",
        "datetime",
        "decimal",
        "difflib",
        "enum",
        "fractions",
        "functools",
        "gzip",
        "hashlib",
        "hmac",
        "html",
        "io",
        "itertools",
        "json",
        "math",
        "mimetypes",
        "numbers",
        "operator",
        "pathlib",
        "pprint",
        "random",
        "re",
        "secrets",
        "stat",
        "statistics",
        "string",
        "struct",
        "sys",
        "tarfile",
        "tempfile",
        "textwrap",
        "time",
        "typing",
        "unicodedata",
        "urllib.parse",
        "uuid",
        "xml.etree.ElementTree",
        "zipfile",
        "zlib",
        "pandas",
        "numpy",
        "yaml",
        "pydantic",
    }
)
_TARGET_CAPABLE_NAMES = frozenset(
    {
        "aiohttp",
        "asyncssh",
        "ctypes",
        "ftplib",
        "httpx",
        "importlib",
        "os",
        "paramiko",
        "playwright",
        "pwn",
        "requests",
        "scapy",
        "selenium",
        "socket",
        "subprocess",
        "sys",
        "telnetlib",
        "urllib",
        "webbrowser",
    }
)
_DYNAMIC_EXECUTION_CALLS = frozenset(
    {
        "__import__",
        "compile",
        "connect",
        "connect_ex",
        "create_connection",
        "eval",
        "exec",
        "execv",
        "execve",
        "fork",
        "popen",
        "spawn",
        "system",
        "urlopen",
    }
)


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
            "execute_code metadata must contain exactly eng_dir, phase, target, and session_id. "
            'Header format (line 1 of code): # violin: {"eng_dir":"<path>","phase":"<phase>","target":"<target>","session_id":"<session_id>"} '
            "(obtain session_id via violin_status)",
        )
    if not all(isinstance(raw[name], str) and raw[name].strip() for name in _REQUIRED_FIELDS):
        return None, "execute_code metadata values must be non-empty strings"
    return {name: raw[name].strip() for name in _REQUIRED_FIELDS}, None


def execution_class(source: object) -> str:
    """Classify whether Python can touch a target or launch another process.

    This changes review accounting, never authorization. Unknown imports and
    dynamic execution primitives fail closed as target-capable.
    """
    tree = ast.parse(str(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name.split(".", 1)[0] not in _LOCAL_ANALYSIS_IMPORTS for alias in node.names
            ):
                return "target_touching"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            if not root or root not in _LOCAL_ANALYSIS_IMPORTS:
                return "target_touching"
        elif isinstance(node, ast.Name) and node.id in _TARGET_CAPABLE_NAMES:
            return "target_touching"
        elif isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if name in _DYNAMIC_EXECUTION_CALLS:
                return "target_touching"
    return "local_analysis"


def validate_source(source: object) -> tuple[dict[str, str] | None, str | None]:
    """Validate metadata against the same engagement gates as command execution."""
    metadata, error = parse_metadata(source)
    if error or metadata is None:
        return None, error
    try:
        tree = ast.parse(str(source))
    except SyntaxError as exc:
        return None, f"execute_code source must parse as Python: {exc.msg}"
    classification = execution_class(source)
    eng_dir = state.resolve_eng_dir(metadata["eng_dir"])
    gate = command.check_command(
        command.CheckCommandArgs(
            command=f"execute_code class={classification} sha256={source_digest(source)}",
            phase=metadata["phase"],
            eng_dir=str(eng_dir),
            scope=str(eng_dir / "scope" / "scope.yaml"),
            target=metadata["target"],
            session_id=metadata["session_id"],
            account_sync=classification == "target_touching",
        )
    )
    if gate.errors:
        return None, "execute_code blocked by Violin guard: " + "; ".join(gate.errors)
    declared = normalize_target(metadata["target"])
    foreign: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value
        if _is_local_path_literal(value):
            continue  # filename/path strings (FIND-*.md, evidence/..., *.json) are not targets
        for candidate in extract_target_candidates(f"probe {value}"):
            normalized = normalize_target(candidate)
            if normalized not in {declared, "localhost", "127.0.0.1", "0.0.0.0", "::1"}:
                foreign.add(normalized)
    if foreign:
        return None, (
            "execute_code contains non-local target literals that differ from declared target: "
            + ", ".join(sorted(foreign))
        )
    return metadata, None


def _is_local_path_literal(value: str) -> bool:
    """True when a string literal is clearly a local file path, not a network target.

    Guards the execute_code target-literal scanner against false positives on
    canonical finding filenames (FIND-NNN.md), evidence paths, and temp paths that
    appear inside code payloads.
    """
    stripped = value.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    if _LOCAL_PATH_RE.search(lowered):
        return True
    if "\\" in stripped:
        return True
    return any(lowered.endswith(ext) for ext in _LOCAL_PATH_EXTENSIONS)


def source_digest(source: object) -> str:
    return hashlib.sha256(str(source).encode("utf-8")).hexdigest()


def prepare_execution(source: object) -> tuple[dict[str, str], Path]:
    """Persist intent and account only for target-capable dispatches."""
    metadata, error = validate_source(source)
    if error or metadata is None:
        raise ValueError(error or "execute_code validation failed")
    eng_dir = state.resolve_eng_dir(metadata["eng_dir"])
    digest = source_digest(source)
    classification = execution_class(source)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    audit_id = str(uuid.uuid4())
    evidence_dir = eng_dir / "evidence" / "executions"
    source_path = evidence_dir / f"{stamp}-{audit_id[:8]}-execute-code.py"
    receipt_path = evidence_dir / f"{stamp}-{audit_id[:8]}-execute-code.json"
    state.ensure_dir(evidence_dir)
    source_path.write_text(str(source), encoding="utf-8")
    command_text = (
        f"execute_code class={classification} sha256={digest} target={metadata['target']}"
    )
    receipt = {
        "schema_version": 1,
        "audit_id": audit_id,
        "status": "starting",
        "command": command_text,
        "execution_class": classification,
        "sync_accounted": classification == "target_touching",
        "source_digest": digest,
        "phase": metadata["phase"],
        "target": metadata["target"],
        "session_id": metadata["session_id"],
        "started_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "evidence_paths": {
            "manifest": receipt_path.relative_to(eng_dir).as_posix(),
            "source": source_path.relative_to(eng_dir).as_posix(),
        },
    }
    state.atomic_json(receipt_path, receipt)
    if classification == "target_touching":
        try:
            active = find_active_task(parse_ptt(eng_dir / "state" / "ptt.md"))
            remaining = _commit_guard_state(
                eng_dir, command_text, metadata["phase"], active.id if active else ""
            )
        except Exception as exc:
            receipt.update(status="failed_to_dispatch", error=str(exc))
            state.atomic_json(receipt_path, receipt)
            raise
    else:
        remaining = state.sync_credit_remaining(eng_dir, metadata["phase"])
    receipt["sync_credit_remaining"] = remaining
    state.atomic_json(receipt_path, receipt)
    return metadata, receipt_path


def record_completion(
    source: object,
    result: object,
    duration_ms: object = 0,
    *,
    receipt_path: str | Path,
) -> Path:
    """Finalize the pre-dispatch receipt and append one explicit history record."""
    metadata, error = parse_metadata(source)
    if error or metadata is None:
        raise ValueError(error or "execute_code metadata is missing")
    eng_dir = state.resolve_eng_dir(metadata["eng_dir"])
    digest = source_digest(source)
    receipt_file = Path(receipt_path)
    receipt = state.read_json(receipt_file)
    if receipt.get("source_digest") != digest:
        raise ValueError("execute_code completion does not match its intent receipt")

    summary = _result_summary(result, duration_ms)
    # Command identity is created before dispatch and is also stored in the
    # pending sync batch.  Keep it byte-for-byte stable so review/rebind can
    # reconcile the completed execution against that batch.  Outcome metadata
    # belongs in the receipt and dedicated history fields, not in command=.
    command_text = str(receipt.get("command") or "").strip()
    if not command_text:
        raise ValueError("execute_code intent receipt has no command identity")
    completed_receipt = {
        **receipt,
        "status": "completed" if summary["status"] == "ok" else "completed_with_error",
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "duration_ms": summary["duration_ms"],
        "exit_code": summary["exit_code"],
    }
    if not history.history_contains(eng_dir, command_text):
        history.append_history(
            eng_dir,
            command_text,
            metadata["phase"],
            summary["exit_code"],
            receipt_file.relative_to(eng_dir).as_posix(),
            status=str(completed_receipt["status"]),
        )
    state.atomic_json(receipt_file, completed_receipt)
    return receipt_file


def abandon_execution(receipt_path: str | Path, reason: str) -> None:
    """Close a prepared intent that cannot receive a post-tool completion."""
    receipt_file = Path(receipt_path)
    receipt = state.read_json(receipt_file)
    if receipt.get("status") != "starting":
        return
    eng_dir = receipt_file.resolve().parents[2]
    command_text = str(receipt.get("command") or "").strip()
    abandoned = {
        **receipt,
        "status": "abandoned",
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "exit_code": -1,
        "error": reason,
    }
    if command_text and not history.history_contains(eng_dir, command_text):
        history.append_history(
            eng_dir,
            command_text,
            str(receipt.get("phase") or "RECON"),
            -1,
            receipt_file.relative_to(eng_dir).as_posix(),
            status="abandoned",
        )
    state.atomic_json(receipt_file, abandoned)


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


__all__ = [
    "abandon_execution",
    "execution_class",
    "parse_metadata",
    "prepare_execution",
    "record_completion",
    "source_digest",
    "validate_source",
]
