from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, hypotheses
from plugins.violin_guard.core.evidence import findings, receipt_integrity
from plugins.violin_guard.handlers.ptt_gates import (
    _validate_phase_exit,
)


def test_proof_byte_warning_states_acceptance_and_the_remedy(tmp_path: Path) -> None:
    """#124: the warning must say the finding still counts as proof and name the remedy."""
    engagement = tmp_path / "engagement"
    proof = engagement / "evidence" / "executions" / "probe.txt"
    proof.parent.mkdir(parents=True)
    proof.write_text(
        'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"ok": true}\n',
        encoding="utf-8",
    )
    relative = ["evidence/executions/probe.txt"]
    assert findings._proof_byte_warnings(engagement, relative, []) == []

    proof.write_text("HTTP/1.1 401 Unauthorized\n", encoding="utf-8")
    warnings = findings._proof_byte_warnings(engagement, relative, [])
    assert warnings
    assert "still accepted as proof" in warnings[0]
    assert "violin_exec" in warnings[0]


def test_submit_finding_accepts_receipt_authenticated_json_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raw HTTP JSON response is evidence, not an execution receipt."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    response = engagement / "evidence/vuln-research/login.json"
    response.parent.mkdir(parents=True, exist_ok=True)
    response.write_text('{"requires_totp": true}', encoding="utf-8")
    receipt = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "login-proof",
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"response": response.relative_to(engagement).as_posix()},
        },
        engagement,
    )
    receipt_path = engagement / "evidence/executions/login-proof.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    record = findings.submit_finding(
        engagement,
        title="Authentication step permits unintended access",
        severity="High",
        summary="Observed access using the first authentication step.",
        receipt_paths=["evidence/executions/login-proof.json"],
        evidence_paths=["evidence/vuln-research/login.json"],
    )
    assert "evidence/vuln-research/login.json" in record["evidence_paths"]


def test_evidence_file_must_not_be_an_execution_receipt(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    receipt_path = engagement / "evidence/executions/login-proof.json"
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text('{"status": "completed"}', encoding="utf-8")
    with pytest.raises(ValueError, match="execution receipts are not decisive evidence"):
        findings._verified_evidence_files(
            engagement,
            ["evidence/executions/login-proof.json"],
            {"evidence/executions/login-proof.json"},
        )


def test_submit_finding_rejects_nonreviewable_cited_receipt_even_with_other_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blocked execution cannot serve as the cited receipt for a finding."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    response = engagement / "evidence/vuln-research/login.json"
    response.parent.mkdir(parents=True, exist_ok=True)
    response.write_text('{"requires_totp": true}', encoding="utf-8")
    receipt_dir = engagement / "evidence/executions"
    receipt_dir.mkdir(parents=True, exist_ok=True)

    unreviewable = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "blocked-proof",
            "status": "precondition_denied",
            "exit_code": None,
            "evidence_paths": {},
        },
        engagement,
    )
    unreviewable_path = receipt_dir / "blocked-proof.json"
    unreviewable_path.write_text(json.dumps(unreviewable), encoding="utf-8")
    valid = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "login-proof",
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"response": response.relative_to(engagement).as_posix()},
        },
        engagement,
    )
    (receipt_dir / "login-proof.json").write_text(json.dumps(valid), encoding="utf-8")

    with pytest.raises(ValueError, match="receipt did not execute to a reviewable result"):
        findings.submit_finding(
            engagement,
            title="Authentication step permits unintended access",
            severity="High",
            summary="Must cite a reviewable execution result.",
            receipt_paths=[unreviewable_path.relative_to(engagement).as_posix()],
            evidence_paths=["evidence/vuln-research/login.json"],
        )


def test_json_evidence_still_requires_receipt_authentication(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    response = engagement / "evidence/vuln-research/response.json"
    response.parent.mkdir(parents=True)
    response.write_text('{"ok": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="authenticated by an execution receipt"):
        findings._verified_evidence_files(
            engagement,
            ["evidence/vuln-research/response.json"],
            set(),
        )


def test_resubmitting_a_finding_updates_one_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#177: a resubmission with stronger evidence folds into the existing record."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    execution_dir = engagement / "evidence" / "executions"
    execution_dir.mkdir(parents=True, exist_ok=True)

    def _seal(execution_id: str, body: str, name: str) -> str:
        proof = execution_dir / name
        proof.write_text(body, encoding="utf-8")
        record = receipt_integrity.seal_execution_receipt(
            {
                "execution_id": execution_id,
                "status": "completed",
                "exit_code": 0,
                "evidence_paths": {"stdout": proof.relative_to(engagement).as_posix()},
            },
            engagement,
        )
        path = execution_dir / f"{name}.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        return path.relative_to(engagement).as_posix()

    first_receipt = _seal(
        "first-run", "HTTP/1.1 200 OK\nContent-Type: text/html\n\nvulnerable\n", "first"
    )
    second_receipt = _seal(
        "second-run",
        'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"admin": true}\n',
        "second",
    )
    stronger_evidence = "evidence/executions/second"

    initial = findings.submit_finding(
        engagement,
        title="IDOR on order lookup",
        severity="High",
        summary="Order lookup returns another tenant's order.",
        receipt_paths=[first_receipt],
    )
    updated = findings.submit_finding(
        engagement,
        title="IDOR on order lookup",
        severity="High",
        summary="Order lookup returns another tenant's order.",
        receipt_paths=[second_receipt],
        evidence_paths=[stronger_evidence],
    )

    records = findings.load_findings(engagement)
    assert len(records) == 1
    assert updated["finding_id"] == initial["finding_id"]
    assert updated["duplicate"] is True
    assert set(records[0]["receipt_paths"]) == {first_receipt, second_receipt}
    assert stronger_evidence in records[0]["evidence_paths"]


def test_stale_receipt_cannot_authenticate_overwritten_shared_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An overwritten shared path is accepted only by its matching receipt."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"c" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    evidence = engagement / "evidence" / "exploitation" / "proof.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("HTTP/1.1 200 OK\ntoken leaked\n", encoding="utf-8")
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Validated issue",
        status="Validated",
        runtime_evidence="evidence/exploitation/proof.txt",
    )

    def write_batch(execution_id: str, body: str) -> str:
        """Run one batch that overwrites the shared evidence path, then seal it."""
        evidence.write_text(body, encoding="utf-8")
        receipt = receipt_integrity.seal_execution_receipt(
            {
                "execution_id": execution_id,
                "status": "completed",
                "exit_code": 0,
                "evidence_paths": {"stdout": "evidence/exploitation/proof.txt"},
            },
            engagement,
        )
        receipt_path = engagement / "evidence" / "executions" / f"{execution_id}.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        return f"evidence/executions/{execution_id}.json"

    first = write_batch("batch-one", "HTTP/1.1 200 OK\ntoken leaked\n")
    second = write_batch("batch-two", "HTTP/1.1 200 OK\ntoken leaked again\n")
    first_receipt_bytes = (engagement / first).read_bytes()
    with pytest.raises(ValueError, match="has changed evidence"):
        findings.submit_finding(
            engagement,
            title="Stale shared evidence",
            severity="High",
            summary="The first receipt must not inherit another receipt's digest.",
            receipt_paths=[first],
        )
    assert (engagement / first).read_bytes() == first_receipt_bytes
    findings.submit_finding(
        engagement,
        title="Current shared evidence",
        severity="High",
        summary="The second receipt authenticates the bytes currently saved.",
        receipt_paths=[second],
    )

    _validate_phase_exit(engagement, "PT-050", "[x]")  # the matching receipt closes

    evidence.write_text("HTTP/1.1 200 OK\nforged\n", encoding="utf-8")
    with pytest.raises(ValueError, match="has changed evidence") as excinfo:
        _validate_phase_exit(engagement, "PT-050", "[x]")
    message = str(excinfo.value)
    assert "this receipt" in message
    assert "re-run the probe" in message


def test_resubmitting_a_different_vulnerability_keeps_two_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The identity rule must not fold two distinct claims into one."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    proof = engagement / "evidence" / "executions" / "one"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("HTTP/1.1 200 OK\nContent-Type: text/html\n\nvulnerable\n", encoding="utf-8")
    receipt = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "run-1",
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"stdout": proof.relative_to(engagement).as_posix()},
        },
        engagement,
    )
    receipt_path = proof.parent / "one.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    relative = receipt_path.relative_to(engagement).as_posix()

    for title in ("IDOR on order lookup", "Stored XSS in the comment field"):
        findings.submit_finding(
            engagement,
            title=title,
            severity="High",
            summary="Distinct claim.",
            receipt_paths=[relative],
        )

    assert len(findings.load_findings(engagement)) == 2
