"""Authenticate execution receipts and their evidence artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RECEIPT_KEY_ENV = "VIOLIN_RECEIPT_KEY"
RECEIPT_SIGNING_KEY_ENV = "VIOLIN_RECEIPT_SIGNING_KEY"
SIGNATURE_FIELD = "receipt_hmac_sha256"
PUBLIC_SIGNATURE_FIELD = "receipt_ed25519"
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
_RUNTIME_SIGNING_KEY = _decode_key(os.environ.pop(RECEIPT_SIGNING_KEY_ENV, None))


def _canonical_receipt(record: dict[str, Any]) -> bytes:
    unsigned = {
        key: value
        for key, value in record.items()
        if key not in {SIGNATURE_FIELD, PUBLIC_SIGNATURE_FIELD}
    }
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _file_digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _evidence_paths(record: dict[str, Any], engagement: Path) -> list[Path]:
    evidence_root = (engagement / "evidence").resolve()
    manifest_value = str((record.get("evidence_paths") or {}).get("manifest") or "")
    values = [
        str(value)
        for value in (record.get("evidence_paths") or {}).values()
        if value and str(value) != manifest_value
    ]
    declared_outputs = record.get("declared_evidence_outputs") or []
    if isinstance(declared_outputs, list):
        values.extend(str(value) for value in declared_outputs)
    paths: list[Path] = []
    for value in values:
        declared = Path(value)
        candidate = (
            declared.resolve() if declared.is_absolute() else (engagement / declared).resolve()
        )
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
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    """Bind a completed receipt to the exact evidence bytes it produced."""
    secret = _decode_key(key) if key is not None else _RUNTIME_KEY
    signer_bytes = _decode_key(signing_key) if signing_key is not None else _RUNTIME_SIGNING_KEY
    sealed = dict(record)
    sealed.pop(SIGNATURE_FIELD, None)
    sealed.pop(PUBLIC_SIGNATURE_FIELD, None)
    sealed.pop(DIGESTS_FIELD, None)
    if secret is None and signer_bytes is None:
        return sealed
    root = engagement.resolve()
    sealed[DIGESTS_FIELD] = {
        path.relative_to(root).as_posix(): _file_digest(path)
        for path in _evidence_paths(sealed, root)
    }
    if signer_bytes is not None:
        signer = Ed25519PrivateKey.from_private_bytes(signer_bytes)
        signature = signer.sign(_canonical_receipt(sealed))
        sealed[PUBLIC_SIGNATURE_FIELD] = f"ed25519:{b64encode(signature).decode('ascii')}"
    else:
        signature = hmac.new(secret, _canonical_receipt(sealed), hashlib.sha256).hexdigest()
        sealed[SIGNATURE_FIELD] = f"hmac-sha256:{signature}"
    return sealed


def verified_evidence_paths(
    record: dict[str, Any],
    engagement: Path,
    *,
    key: str | bytes | None = None,
    public_key: str | bytes | None = None,
) -> tuple[Path, ...] | None:
    """Return authenticated, unchanged evidence paths or fail closed."""
    public_signature = str(record.get(PUBLIC_SIGNATURE_FIELD) or "")
    if public_signature.startswith("ed25519:") and public_key is not None:
        try:
            verifier_bytes = (
                public_key if isinstance(public_key, bytes) else bytes.fromhex(public_key)
            )
            verifier = Ed25519PublicKey.from_public_bytes(verifier_bytes)
            verifier.verify(
                b64decode(public_signature.removeprefix("ed25519:"), validate=True),
                _canonical_receipt(record),
            )
        except (ValueError, InvalidSignature):
            return None
    else:
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


def verify_runtime_receipt(record: dict[str, Any], engagement: Path) -> tuple[Path, ...] | None:
    """Verify a receipt inside the guard process without exposing signing material."""
    if _RUNTIME_SIGNING_KEY is not None:
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(_RUNTIME_SIGNING_KEY)
        except ValueError:
            return None
        public_key = private_key.public_key().public_bytes_raw()
        return verified_evidence_paths(record, engagement, public_key=public_key)
    return verified_evidence_paths(record, engagement, key=_RUNTIME_KEY)


__all__ = [
    "DIGESTS_FIELD",
    "RECEIPT_KEY_ENV",
    "RECEIPT_SIGNING_KEY_ENV",
    "PUBLIC_SIGNATURE_FIELD",
    "SIGNATURE_FIELD",
    "seal_execution_receipt",
    "verify_runtime_receipt",
    "verified_evidence_paths",
]
