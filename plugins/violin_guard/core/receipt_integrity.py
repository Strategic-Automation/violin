"""Authenticate execution receipts and their evidence artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shlex
from pathlib import Path
from typing import Any

RECEIPT_KEY_ENV = "VIOLIN_RECEIPT_KEY"
SIGNATURE_FIELD = "receipt_hmac_sha256"
DIGESTS_FIELD = "evidence_sha256"


def _decode_key(value: str | bytes | None) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value if len(value) >= 32 else None
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return None
    return decoded if len(decoded) >= 32 else None


# The runner injects this only into the Hermes process. Remove it from the
# process environment as the plugin loads so target commands cannot inherit it.
_RUNTIME_KEY = _decode_key(os.environ.pop(RECEIPT_KEY_ENV, None))


def _canonical_receipt(record: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in record.items() if key != SIGNATURE_FIELD}
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _file_digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _declared_output_values(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return []
    values: list[str] = []
    for index, token in enumerate(tokens):
        if token in {"-o", "--output"} and index + 1 < len(tokens):
            values.append(tokens[index + 1])
        elif token.startswith("--output="):
            values.append(token.partition("=")[2])
    return values


def _evidence_paths(record: dict[str, Any], engagement: Path) -> list[Path]:
    evidence_root = (engagement / "evidence").resolve()
    manifest_value = str((record.get("evidence_paths") or {}).get("manifest") or "")
    values = [
        str(value)
        for value in (record.get("evidence_paths") or {}).values()
        if value and str(value) != manifest_value
    ]
    values.extend(_declared_output_values(str(record.get("command") or "")))
    paths: list[Path] = []
    for value in values:
        relative = Path(value)
        if relative.is_absolute():
            continue
        candidate = (engagement / relative).resolve()
        if (
            candidate.is_relative_to(evidence_root)
            and candidate.is_file()
            and not candidate.is_symlink()
            and candidate not in paths
        ):
            paths.append(candidate)
    return paths


def seal_execution_receipt(
    record: dict[str, Any],
    engagement: Path,
    *,
    key: str | bytes | None = None,
) -> dict[str, Any]:
    """Bind a completed receipt to the exact evidence bytes it produced."""
    secret = _decode_key(key) if key is not None else _RUNTIME_KEY
    sealed = dict(record)
    sealed.pop(SIGNATURE_FIELD, None)
    sealed.pop(DIGESTS_FIELD, None)
    if secret is None:
        return sealed
    root = engagement.resolve()
    sealed[DIGESTS_FIELD] = {
        path.relative_to(root).as_posix(): _file_digest(path)
        for path in _evidence_paths(sealed, root)
    }
    signature = hmac.new(secret, _canonical_receipt(sealed), hashlib.sha256).hexdigest()
    sealed[SIGNATURE_FIELD] = f"hmac-sha256:{signature}"
    return sealed


def verified_evidence_paths(
    record: dict[str, Any],
    engagement: Path,
    *,
    key: str | bytes | None,
) -> tuple[Path, ...] | None:
    """Return authenticated, unchanged evidence paths or fail closed."""
    secret = _decode_key(key)
    signature = str(record.get(SIGNATURE_FIELD) or "")
    if secret is None or not signature.startswith("hmac-sha256:"):
        return None
    expected = hmac.new(secret, _canonical_receipt(record), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.removeprefix("hmac-sha256:"), expected):
        return None
    digests = record.get(DIGESTS_FIELD)
    if not isinstance(digests, dict):
        return None
    evidence_root = (engagement / "evidence").resolve()
    verified: list[Path] = []
    for value, expected_digest in digests.items():
        relative = Path(str(value))
        candidate = (engagement / relative).resolve()
        if (
            relative.is_absolute()
            or not candidate.is_relative_to(evidence_root)
            or not candidate.is_file()
            or candidate.is_symlink()
            or not hmac.compare_digest(_file_digest(candidate), str(expected_digest))
        ):
            return None
        verified.append(candidate)
    return tuple(verified)


__all__ = [
    "DIGESTS_FIELD",
    "RECEIPT_KEY_ENV",
    "SIGNATURE_FIELD",
    "seal_execution_receipt",
    "verified_evidence_paths",
]
