"""Contract tests for benchmark evidence behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.proof import match_finding
from benchmark.score import load_golden_set
from plugins.violin_guard.core.evidence import findings, receipt_integrity
from plugins.violin_guard.handlers.finding_handlers import handle_submit_finding
from tests.benchmark.receipt_fixture import _write_receipt


def test_absence_challenge_credits_bare_status_code_burst() -> None:
    # `curl -w '%{http_code} '` in a burst probe emits a line of bare 3-digit
    # statuses ("401 401 ... 401"); no-rate-limiting (absence) must count them
    # as ≥8 identical statuses, not treat the line as unstructured text.
    from benchmark.proof import ProofBundle, _absence_result

    bundle = ProofBundle(
        receipt_path=Path("x.json"),
        command="curl -w '%{http_code} ' https://example.test/login",
        proof="401 401 401 401 401 401 401 401 401 401 401 401\n",
        requests=(),
        executed=True,
    )
    assert _absence_result(bundle) is True


def test_absence_challenge_credits_labeled_status_burst() -> None:
    # `curl -w 'req $i %{http_code}\n'` emits one line per request with the
    # status as the TRAILING token ("req 1 401"); absence challenges must still
    # parse each trailing 401 (≥8 identical) rather than skip the labeled lines.
    from benchmark.proof import ProofBundle, _absence_result

    proof = "".join(f"req {i} 401\n" for i in range(1, 13))
    bundle = ProofBundle(
        receipt_path=Path("x.json"),
        command="curl -w 'req $i %{http_code}\\n' https://example.test/login",
        proof=proof,
        requests=(),
        executed=True,
    )
    assert _absence_result(bundle) is True


def test_submit_finding_warns_when_proof_lacks_http_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    # stdout holds only status lines — no response bytes anywhere in the proof chain
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command="curl -sS -i https://example.test/api/items > evidence/probe.txt; grep '^HTTP' evidence/probe.txt",
        proof="HTTP/1.1 200 OK\r\nHTTP/1.1 403 Forbidden\r\n",
    )

    submitted = findings.submit_finding(
        tmp_path,
        title="Status-line-only proof",
        severity="Medium",
        summary="Proof chain carries no HTTP response bytes.",
        receipt_paths=[receipt_path],
    )

    assert submitted["finding_id"] == "FIND-001"
    warnings = submitted.get("warnings", [])
    assert any("evidence_paths" in w and "HTTP" in w for w in warnings), warnings


def test_submit_finding_handler_surfaces_incomplete_proof_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command="curl -sS -i https://example.test/api/items",
        proof="HTTP/1.1 200 OK\r\n",
    )

    result = json.loads(
        handle_submit_finding(
            {
                "eng_dir": str(tmp_path),
                "title": "Status-line-only proof",
                "severity": "Medium",
                "summary": "Proof chain carries no HTTP response bytes.",
                "receipt_paths": [receipt_path],
                "evidence_paths": [],
            }
        )
    )

    assert result["status"] == "ok"
    assert result["evidence_complete"] is False
    assert any("HTTP" in warning for warning in result["warnings"])


def test_submit_finding_rejects_evidence_not_authenticated_by_cited_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command="curl -sS -i https://example.test/api/items",
        proof="HTTP/1.1 200 OK\r\n",
    )
    unattested = tmp_path / "evidence" / "forged-response.txt"
    unattested.write_text(
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"role":"admin"}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="authenticated by an execution receipt"):
        findings.submit_finding(
            tmp_path,
            title="Unattested proof",
            severity="High",
            summary="This proof was not produced by the cited receipt.",
            receipt_paths=[receipt_path],
            evidence_paths=["evidence/forged-response.txt"],
        )


def test_forged_receipt_cannot_authenticate_saved_evidence(tmp_path: Path) -> None:
    execution_dir = tmp_path / "evidence" / "executions"
    execution_dir.mkdir(parents=True)
    forged_body = tmp_path / "evidence" / "forged-admin-response.txt"
    forged_body.write_text(
        "POST /api/v1/auth/login HTTP/1.1\n"
        "HTTP/1.1 200 OK\n"
        '{"username":"admin","password":"admin","access_token":"forged"}\n',
        encoding="utf-8",
    )
    forged_receipt = execution_dir / "forged.json"
    forged_receipt.write_text(
        json.dumps(
            {
                "execution_id": "forged",
                "command": "curl -i -d 'username=admin&password=admin' https://example.test/api/v1/auth/login",
                "status": "completed",
                "exit_code": 0,
                "evidence_paths": {
                    "stdout": forged_body.relative_to(tmp_path).as_posix(),
                },
            }
        ),
        encoding="utf-8",
    )

    _golden_id, candidates = match_finding(
        tmp_path,
        {
            "receipt_paths": [forged_receipt.relative_to(tmp_path).as_posix()],
            "evidence_paths": [forged_body.relative_to(tmp_path).as_posix()],
        },
        load_golden_set(),
        receipt_key=b"k" * 32,
    )

    assert candidates == []


def test_submit_finding_no_warning_with_evidence_file_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command="curl -sS -i https://example.test/api/items",
        proof='HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"leaked":"pii"}',
    )

    submitted = findings.submit_finding(
        tmp_path,
        title="Bytes present in receipt stdout",
        severity="Medium",
        summary="Receipt stdout carries status line plus body.",
        receipt_paths=[receipt_path],
    )

    assert submitted["finding_id"] == "FIND-001"
    assert not submitted.get("warnings"), submitted.get("warnings")


@pytest.mark.parametrize("scripted", [False, True])
def test_only_actual_script_requests_support_receipt_inference(tmp_path, scripted):
    from benchmark.proof import receipt_bundles

    script = tmp_path / "probe.py"
    call = "requests.post('https://example.test/api/v1/auth/login/totp')"
    script.write_text(call if scripted else "# " + call, encoding="utf-8")
    relative = _write_receipt(
        tmp_path,
        key=b"s" * 32,
        command="python3 probe.py",
        proof='HTTP/1.1 200 OK\n{"2fa":"bypassed","token":"signed"}\n',
    )
    bundles = receipt_bundles(tmp_path, [relative], receipt_key=b"s" * 32)
    assert bool(bundles) is scripted
    if scripted:
        assert [(item.method, item.url.path) for item in bundles[0].requests] == [
            ("POST", "/api/v1/auth/login/totp")
        ]
    # A second request must not inherit the first one's unstructured response.
    relative = _write_receipt(
        tmp_path,
        key=b"s" * 32,
        command="python3 probe.py; curl https://example.test/other",
        proof="HTTP/1.1 200 OK\n",
    )
    assert not receipt_bundles(tmp_path, [relative], receipt_key=b"s" * 32)
