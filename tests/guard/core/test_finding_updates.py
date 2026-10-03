"""Finding updates preserve a validated persistent storage contract."""

import json

import pytest
from pydantic import ValidationError

from plugins.violin_guard.core import schemas
from plugins.violin_guard.core.evidence import findings, receipt_integrity


def test_updates_accumulate_more_receipts_than_one_request_allows(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"f" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipts = []
    for index in range(9):
        relative = f"evidence/executions/{index}.json"
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        output = f"evidence/proof-{index}.txt"
        (tmp_path / output).write_text("HTTP/1.1 200 OK\nproof\n", encoding="utf-8")
        receipt = receipt_integrity.seal_execution_receipt(
            {
                "execution_id": str(index),
                "status": "completed",
                "exit_code": 0,
                "declared_evidence_outputs": [output],
            },
            tmp_path,
        )
        path.write_text(json.dumps(receipt), encoding="utf-8")
        receipts.append(relative)

    claim = {"title": "One finding", "severity": "High", "summary": "Verified proof"}
    for batch in (receipts[:8], receipts[8:]):
        schemas.SubmitFindingArgsModel(eng_dir=str(tmp_path), receipt_paths=batch, **claim)
        findings.submit_finding(tmp_path, receipt_paths=batch, **claim)
    stored = findings.load_findings(tmp_path)
    assert len(stored) == 1
    assert stored[0]["receipt_paths"] == receipts
    assert len(stored[0]["execution_ids"]) == 9
    findings.generate_report_md(tmp_path, target="example.test")
    with pytest.raises(ValidationError):
        schemas.SubmitFindingArgsModel(eng_dir=str(tmp_path), receipt_paths=receipts, **claim)

    path = tmp_path / findings.FINDINGS_PATH
    before = path.read_bytes()
    with pytest.raises(ValidationError):
        findings.submit_finding(
            tmp_path, receipt_paths=receipts[-1:], **{**claim, "severity": "invalid"}
        )
    assert path.read_bytes() == before
