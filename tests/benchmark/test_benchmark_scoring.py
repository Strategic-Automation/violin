"""Contract tests for benchmark scoring behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.proof import match_finding
from benchmark.score import load_golden_manifest, load_golden_set, score_engagement
from plugins.violin_guard.core.evidence import findings, receipt_integrity
from tests.benchmark.receipt_fixture import _write_receipt


def test_private_golden_declares_the_article_parity_contract() -> None:
    manifest = load_golden_manifest()
    contract = manifest["contract"]
    assert manifest["total_challenges"] == len(manifest["challenges"]) == 20
    assert contract["id"] == "escape-duck-store-2026-04"
    assert contract["mode"] == "grey-box"
    assert "/openapi.json" in contract["provided_inputs"]
    assert contract["current_catalog_total"] == 23
    assert set(contract["current_catalog_exclusions"]) == {
        "negative-price",
        "mcp-no-auth",
        "mcp-coupon-disclosure",
    }


def test_submit_finding_accepts_only_authenticated_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command="curl https://example.test/api/items",
        proof='{"type":"http_observation","method":"GET","url":"https://example.test/api/items","status":200}',
    )

    submitted = findings.submit_finding(
        tmp_path,
        title="Unauthorized item access",
        severity="High",
        summary="A different user's item was returned.",
        receipt_paths=[receipt_path],
    )

    assert submitted["finding_id"] == "FIND-001"
    assert submitted["receipt_validation"] == "verified"
    assert findings.load_findings(tmp_path)[0]["title"] == "Unauthorized item access"


def test_submit_finding_rejects_changed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command="curl https://example.test/api/items",
        proof="HTTP/1.1 200 OK\n",
    )
    (tmp_path / "evidence" / "executions" / "proof.stdout.txt").write_text(
        "HTTP/1.1 500 Internal Server Error\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="has changed evidence"):
        findings.submit_finding(
            tmp_path,
            title="Claim",
            severity="High",
            summary="Claimed result.",
            receipt_paths=[receipt_path],
        )


def test_private_match_is_endpoint_bound_and_unambiguous(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    proof = evidence / "totp.md"
    proof.write_text(
        "POST /api/v1/auth/login/totp HTTP/1.1\n"
        "HTTP/1.1 200 OK\n"
        '{"2fa":"bypassed","token":"signed"}\n',
        encoding="utf-8",
    )
    golden_id, candidates = match_finding(
        tmp_path,
        {"receipt_paths": ["evidence/totp.md"]},
        load_golden_set(),
        trusted_fixture=True,
    )
    assert golden_id == "totp-bypass"
    assert candidates == ["totp-bypass"]


def test_normal_shipping_response_is_not_credited(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    proof = evidence / "shipping.md"
    proof.write_text(
        "POST /api/v1/orders/checkout HTTP/1.1\n"
        "HTTP/1.1 200 OK\n"
        '{"shipping_cost":10,"status":"paid"}\n',
        encoding="utf-8",
    )
    golden_id, candidates = match_finding(
        tmp_path,
        {"receipt_paths": ["evidence/shipping.md"]},
        load_golden_set(),
        trusted_fixture=True,
    )
    assert golden_id is None
    assert "shipping-bypass" not in candidates


def test_normal_user_login_is_not_credited_as_weak_admin_credentials(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    proof = evidence / "user-login.md"
    proof.write_text(
        "POST /api/v1/auth/login HTTP/1.1\n"
        "Content-Type: application/json\n\n"
        '{"username":"user","password":"password"}\n'
        "HTTP/1.1 200 OK\n"
        '{"access_token":"regular-user-token"}\n',
        encoding="utf-8",
    )
    _golden_id, candidates = match_finding(
        tmp_path,
        {"receipt_paths": ["evidence/user-login.md"]},
        load_golden_set(),
        trusted_fixture=True,
    )
    assert "weak-admin-creds" not in candidates


def test_calibration_known_good_matches_every_golden_case() -> None:
    result = score_engagement(
        Path("benchmark/targets/duck-store/calibration/known-good"),
        trusted_fixture=True,
    )
    assert result["confirmed"] == result["total"] == 20
    assert result["benchmark_pass"] is True


def test_calibration_known_bad_receives_no_credit() -> None:
    fixture = Path("benchmark/targets/duck-store/calibration/known-bad")
    assert fixture.is_dir()
    assert len(findings.load_findings(fixture)) == 3
    result = score_engagement(fixture, trusted_fixture=True)
    assert result["confirmed"] == 0
    assert len(result["unmatched_findings"]) == 3
    assert result["benchmark_pass"] is False


def test_one_submission_can_confirm_multiple_distinct_cases(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    fixture_root = Path("benchmark/targets/duck-store/calibration/known-good/evidence")
    receipt_paths = []
    for name in ("coupon-100-discount.md", "coupon-info-disclosure.md"):
        destination = evidence / name
        destination.write_text((fixture_root / name).read_text(encoding="utf-8"), encoding="utf-8")
        receipt_paths.append(destination.relative_to(tmp_path).as_posix())
    finding = {
        "finding_id": "FIND-001",
        "title": "Coupon system weaknesses",
        "severity": "High",
        "summary": "Two independently reproduced coupon weaknesses.",
        "status": "validated",
        "receipt_paths": receipt_paths,
    }
    (evidence / "findings.jsonl").write_text(json.dumps(finding) + "\n", encoding="utf-8")

    result = score_engagement(tmp_path, trusted_fixture=True)

    confirmed_ids = {detail["golden_id"] for detail in result["confirmed_details"]}
    assert confirmed_ids == {"coupon-100-discount", "coupon-info-disclosure"}
    assert result["confirmed"] == 2
    assert len(result["multi_case_findings"]) == 1


def test_demonstrated_score_exposes_proof_that_was_not_submitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    _write_receipt(
        tmp_path,
        key=key,
        command=(
            "curl -X POST https://duck-store.escape.tech/api/v1/auth/login "
            '-d \'{"username":"admin","password":"admin"}\''
        ),
        proof=(
            'HTTP/1.1 200 OK\n{"access_token":"admin-token",'
            '"user":{"username":"admin","role":"admin"}}\n'
        ),
    )

    result = score_engagement(tmp_path, receipt_key=key)

    assert result["confirmed"] == 0
    assert result["demonstrated"] == 1
    assert result["unreported_demonstrated_ids"] == ["weak-admin-creds"]
