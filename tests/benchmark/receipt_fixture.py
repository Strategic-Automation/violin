"""Shared evidence receipt setup for benchmark tests."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard.core.evidence import receipt_integrity


def _write_receipt(
    engagement: Path,
    *,
    key: bytes,
    command: str,
    proof: str,
    declared_evidence_outputs: list[str] | None = None,
    status: str = "completed",
) -> str:
    execution_dir = engagement / "evidence" / "executions"
    execution_dir.mkdir(parents=True, exist_ok=True)
    proof_path = execution_dir / "proof.stdout.txt"
    proof_path.write_text(proof, encoding="utf-8")
    receipt_path = execution_dir / "proof.json"
    record = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "exec-1",
            "command": command,
            "status": status,
            "exit_code": 0,
            "evidence_paths": {"stdout": proof_path.relative_to(engagement).as_posix()},
            "declared_evidence_outputs": declared_evidence_outputs or [],
        },
        engagement,
        key=key,
    )
    receipt_path.write_text(json.dumps(record), encoding="utf-8")
    return receipt_path.relative_to(engagement).as_posix()
