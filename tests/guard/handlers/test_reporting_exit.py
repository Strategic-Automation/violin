from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, hypotheses
from plugins.violin_guard.core.evidence import findings, history, receipt_integrity
from plugins.violin_guard.handlers.ptt_gates import (
    _validate_phase_exit,
)


def test_reporting_exit_accepts_uppercase_phase_token_in_audit_mode(tmp_path: Path) -> None:
    """REPORTING gate must match the canonical UPPERCASE phase token that
    violin_exec records verbatim (phase=EXPLOITATION), not only lowercase."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    history = engagement / "state" / "history.md"
    history.write_text(
        "# Command History\n"
        "- 2026-08-11T12:00:00Z | phase=RECON | exit_code=0 | command=curl x\n"
        "- 2026-08-11T12:05:00Z | phase=EXPLOITATION | exit_code=0 | command=curl y\n",
        encoding="utf-8",
    )
    # Uppercase EXPLOITATION must be recognised by the phase-history gate.
    # With no Validated hypothesis on the board, the exit may pass entirely or
    # raise a *different* (downstream) error — the point is it must NOT raise
    # the "no commands were executed in EXPLOITATION" phase-history error.
    try:
        _validate_phase_exit(engagement, "PT-050", "[x]")
    except ValueError as exc:
        assert "no commands were executed in EXPLOITATION" not in str(exc.value)


def test_reporting_exit_blocks_recon_only_run_in_audit_mode(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    history = engagement / "state" / "history.md"
    history.write_text(
        "# Command History\n- 2026-08-11T12:00:00Z | phase=recon | exit_code=0 | command=curl x\n"
        "- 2026-08-11T12:01:00Z | phase=recon | exit_code=0 | command=curl y\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no commands were executed in EXPLOITATION"):
        _validate_phase_exit(engagement, "PT-050", "[x]")


def test_reporting_exit_allows_exploitation_history_in_audit_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    history = engagement / "state" / "history.md"
    history.write_text(
        "# Command History\n- 2026-08-11T12:00:00Z | phase=recon | exit_code=0 | command=curl x\n"
        "- 2026-08-11T12:05:00Z | phase=exploitation | exit_code=0 | command=curl y\n",
        encoding="utf-8",
    )
    evidence = engagement / "evidence" / "exploitation" / "proof.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("decisive runtime proof\n", encoding="utf-8")
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Validated issue",
        status="Validated",
        runtime_evidence="evidence/exploitation/proof.txt",
    )
    with pytest.raises(ValueError, match="validated hypotheses without a receipt-backed finding"):
        _validate_phase_exit(engagement, "PT-050", "[x]")
    receipt = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "reporting-proof",
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"stdout": "evidence/exploitation/proof.txt"},
        },
        engagement,
    )
    receipt_path = engagement / "evidence/executions/reporting-proof.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    findings.submit_finding(
        engagement,
        title="Validated issue",
        severity="High",
        summary="Reproduced with authenticated runtime evidence.",
        receipt_paths=["evidence/executions/reporting-proof.json"],
    )
    _validate_phase_exit(engagement, "PT-050", "[x]")
    evidence.write_text("changed evidence", encoding="utf-8")
    with pytest.raises(ValueError, match="changed evidence"):
        _validate_phase_exit(engagement, "PT-050", "[x]")


def test_reporting_exit_accepts_hypothesis_with_superset_runtime_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#181: a hypothesis whose runtime_evidence is a strict superset of its finding's
    receipt-authenticated evidence still closes. The gate requires OVERLAP (the finding
    cites at least one runtime-evidence path), not a strict subset, so a hypothesis that
    records everything it rested on is not penalised."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    history_md = engagement / "state" / "history.md"
    history_md.write_text(
        "# Command History\n"
        "- 2026-08-11T12:05:00Z | phase=exploitation | exit_code=0 | command=curl y\n",
        encoding="utf-8",
    )
    for name in ("proof.txt", "extra.txt"):
        path = engagement / "evidence" / "exploitation" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("decisive runtime proof\n", encoding="utf-8")
    # Hypothesis records BOTH files; the finding's receipt authenticates only one.
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Validated issue",
        status="Validated",
        runtime_evidence="evidence/exploitation/proof.txt, evidence/exploitation/extra.txt",
    )
    receipt = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "reporting-proof",
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"stdout": "evidence/exploitation/proof.txt"},
        },
        engagement,
    )
    receipt_path = engagement / "evidence/executions/reporting-proof.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    findings.submit_finding(
        engagement,
        title="Validated issue",
        severity="High",
        summary="Reproduced with authenticated runtime evidence.",
        receipt_paths=["evidence/executions/reporting-proof.json"],
    )
    _validate_phase_exit(engagement, "PT-050", "[x]")  # no exception despite superset


def test_reporting_close_accepts_receipt_backed_vuln_research_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#175: validation PoCs legitimately run under VULN_RESEARCH, so a receipt-backed
    one satisfies the reporting close — while a receipt-less one is refused by naming
    the exact command whose receipt would satisfy it."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    command_text = "curl -sS http://10.10.10.10/validate"
    evidence = engagement / "evidence" / "vuln_research" / "proof.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("decisive validation proof\n", encoding="utf-8")
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Validated issue",
        status="Validated",
        runtime_evidence="evidence/vuln_research/proof.txt",
    )
    receipt = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": "validation-proof",
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"stdout": "evidence/vuln_research/proof.txt"},
        },
        engagement,
    )
    receipt_path = engagement / "evidence/executions/validation-proof.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    findings.submit_finding(
        engagement,
        title="Validated issue",
        severity="High",
        summary="Reproduced with authenticated validation evidence.",
        receipt_paths=["evidence/executions/validation-proof.json"],
    )
    history.append_history(engagement, command_text, "VULN_RESEARCH", 0)

    with pytest.raises(ValueError) as failure:
        _validate_phase_exit(engagement, "PT-050", "[x]")
    assert command_text in str(failure.value)

    history.append_history(
        engagement,
        command_text,
        "VULN_RESEARCH",
        0,
        receipt_path="evidence/executions/validation-proof.json",
    )
    _validate_phase_exit(engagement, "PT-050", "[x]")
