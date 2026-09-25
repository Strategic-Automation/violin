"""A receipt authenticates each evidence file independently.

#203: ``violin_exec_burst`` stamps one batch-wide ``evidence_outputs`` union on
every command, so a receipt also sealed the files its batch-mates produced. When
any of those was rewritten later, the whole receipt stopped authenticating and
``violin_submit_finding`` rejected findings resting on unrelated evidence.

The contract these tests pin:
* a receipt seals only the files its own command wrote;
* a sealed file whose bytes changed is stale, and never disqualifies its siblings;
* citing a stale file fails naming the file that conflicts.
"""

import json
from pathlib import Path

import pytest

from plugins.violin_guard.core.evidence import findings, receipt_integrity

KEY = b"r" * 32


@pytest.fixture(autouse=True)
def _runtime_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", KEY)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)


def _sealed_evidence(engagement: Path) -> tuple[dict, Path, Path]:
    """A receipt sealing two evidence files, one of which is about to change."""
    first = engagement / "evidence" / "recon" / "first.txt"
    second = engagement / "evidence" / "recon" / "second.txt"
    first.parent.mkdir(parents=True)
    first.write_text("first\n", encoding="utf-8")
    second.write_text("second\n", encoding="utf-8")
    receipt = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "file-by-file",
            "status": "completed",
            "exit_code": 0,
            "declared_evidence_outputs": [
                "evidence/recon/first.txt",
                "evidence/recon/second.txt",
            ],
        },
        engagement,
    )
    return receipt, first, second


def _write_receipt(engagement: Path, name: str, receipt: dict) -> str:
    relative = f"evidence/executions/{name}.json"
    path = engagement / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return relative


def test_evidence_is_authenticated_file_by_file(tmp_path: Path) -> None:
    """One rewritten artifact must not cost a receipt the evidence it still proves."""
    engagement = tmp_path
    receipt, first, second = _sealed_evidence(engagement)

    second.write_text("rewritten\n", encoding="utf-8")

    state = receipt_integrity.verify_runtime_receipt(receipt, engagement)
    assert state.authenticated == (first.resolve(),)
    assert state.stale == ("evidence/recon/second.txt",)
    assert receipt_integrity.verified_evidence_paths(receipt, engagement, key=KEY) == (
        first.resolve(),
    )


def test_an_evidence_receipt_with_nothing_left_is_rejected(tmp_path: Path) -> None:
    """Fail closed when every sealed file has changed: there is no proof left."""
    engagement = tmp_path
    receipt, _, _ = _sealed_evidence(engagement)

    for value in ("evidence/recon/first.txt", "evidence/recon/second.txt"):
        (engagement / value).write_text("rewritten\n", encoding="utf-8")

    assert receipt_integrity.verified_evidence_paths(receipt, engagement, key=KEY) is None
    assert receipt_integrity.verify_runtime_receipt(receipt, engagement).stale == (
        "evidence/recon/first.txt",
        "evidence/recon/second.txt",
    )


def test_intact_evidence_still_submits_after_a_sibling_changes(tmp_path: Path) -> None:
    """Findings rest on the files they cite, not on every file a receipt sealed."""
    engagement = tmp_path
    receipt, _, second = _sealed_evidence(engagement)
    receipt_path = _write_receipt(engagement, "intact-sibling", receipt)
    second.write_text("rewritten\n", encoding="utf-8")

    findings.submit_finding(
        engagement,
        title="Rests on the intact file",
        severity="High",
        summary="Reproduced with receipt-authenticated evidence.",
        receipt_paths=[receipt_path],
        evidence_paths=["evidence/recon/first.txt"],
    )


def test_citing_stale_evidence_names_the_conflicting_file(tmp_path: Path) -> None:
    engagement = tmp_path
    receipt, _, second = _sealed_evidence(engagement)
    receipt_path = _write_receipt(engagement, "stale-cite", receipt)
    second.write_text("rewritten\n", encoding="utf-8")

    with pytest.raises(ValueError, match="has changed evidence: evidence/recon/second.txt"):
        findings.submit_finding(
            engagement,
            title="Cites rewritten evidence",
            severity="High",
            summary="Rests on bytes the receipt no longer authenticates.",
            receipt_paths=[receipt_path],
            evidence_paths=["evidence/recon/second.txt"],
        )


def test_citing_a_receipt_that_has_no_proof_left_is_rejected(tmp_path: Path) -> None:
    engagement = tmp_path
    receipt, first, second = _sealed_evidence(engagement)
    receipt_path = _write_receipt(engagement, "all-stale", receipt)
    first.write_text("rewritten\n", encoding="utf-8")
    second.write_text("rewritten\n", encoding="utf-8")

    with pytest.raises(ValueError, match="has changed evidence"):
        findings.submit_finding(
            engagement,
            title="Rests on rewritten evidence",
            severity="High",
            summary="Rests on bytes the receipt no longer authenticates.",
            receipt_paths=[receipt_path],
        )
