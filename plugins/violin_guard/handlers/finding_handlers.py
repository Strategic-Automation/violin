"""Generic receipt-backed finding submission handler."""

from __future__ import annotations

from ..core import findings
from .base import _json, _serialize_errors


@_serialize_errors
def handle_submit_finding(args: dict, **kwargs) -> str:
    result = findings.submit_finding(
        args["eng_dir"],
        title=args["title"],
        severity=args["severity"],
        summary=args["summary"],
        receipt_paths=args["receipt_paths"],
        evidence_paths=args.get("evidence_paths") or [],
    )
    return _json(
        "ok",
        finding_id=result["finding_id"],
        status=result["status"],
        duplicate=result["duplicate"],
        receipt_validation=result["receipt_validation"],
        evidence_complete=True,
    )
