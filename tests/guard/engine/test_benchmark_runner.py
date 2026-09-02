"""Contract tests for the receipt-backed private benchmark evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.proof import _command_requests, match_finding
from benchmark.run import (
    _hermes_environment,
    _scope_for_target,
    init_benchmark_engagement,
    parse_args,
)
from benchmark.score import load_golden_manifest, load_golden_set, score_engagement
from plugins.violin_guard.core import findings, receipt_integrity
from plugins.violin_guard.handlers.finding_handlers import handle_submit_finding


def _write_receipt(
    engagement: Path,
    *,
    key: bytes,
    command: str,
    proof: str,
    declared_evidence_outputs: list[str] | None = None,
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
            "status": "completed",
            "exit_code": 0,
            "evidence_paths": {"stdout": proof_path.relative_to(engagement).as_posix()},
            "declared_evidence_outputs": declared_evidence_outputs or [],
        },
        engagement,
        key=key,
    )
    receipt_path.write_text(json.dumps(record), encoding="utf-8")
    return receipt_path.relative_to(engagement).as_posix()


def test_agent_scope_contains_routes_but_no_evaluator_identity() -> None:
    scope = _scope_for_target("https://duck-store.escape.tech")
    serialized = json.dumps(scope).casefold()
    assert "post /api/v1/auth/login" in serialized
    assert scope["benchmark"]["openapi_spec"].endswith("/openapi.json")
    assert "/openapi.json" not in scope["exclusions"]["paths"]
    assert "/vulnerabilities" in scope["exclusions"]["paths"]
    assert "challenge" not in serialized
    assert "golden" not in serialized


def test_benchmark_runner_does_not_select_model_or_provider_defaults() -> None:
    args = parse_args([])
    assert args.model == ""
    assert args.provider == ""
    assert args.api_base == ""


def test_hermes_environment_forwards_only_selected_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "selected-key")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-leak")
    monkeypatch.setenv("NOUS_API_KEY", "other-provider-key")
    args = parse_args(
        [
            "--provider",
            "openrouter",
            "--api-base",
            "https://openrouter.ai/api/v1",
        ]
    )

    env = _hermes_environment(args, tmp_path, b"s" * 32)

    assert env["OPENROUTER_API_KEY"] == "selected-key"
    assert env["OPENAI_API_KEY"] == "selected-key"
    assert env["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"
    assert "NOUS_API_KEY" not in env
    assert "UNRELATED_SECRET" not in env


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


def test_agent_scope_rewrites_openapi_input_for_an_isolated_target() -> None:
    scope = _scope_for_target("http://localhost:8080")
    assert scope["benchmark"]["openapi_spec"] == "http://localhost:8080/openapi.json"
    brief = scope["engagement"]["brief"]
    assert "http://localhost:8080/openapi.json" in brief
    assert "https://duck-store.escape.tech" not in brief


def test_initialized_hypothesis_board_has_no_evaluator_fields(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    init_benchmark_engagement(engagement, "https://duck-store.escape.tech")
    board = (engagement / "hypotheses.md").read_text(encoding="utf-8").casefold()
    assert "challenge" not in board
    assert "golden" not in board


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
    result = score_engagement(
        Path("benchmark/targets/duck-store/calibration/known-bad"),
        trusted_fixture=True,
    )
    assert result["confirmed"] == 0
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


def test_command_requests_recovers_urls_from_nested_sh_c_wrapper() -> None:
    # A `sh -c 'python3 - <<PY ... curl ... PY ...'` wrapper collapses to a
    # single shlex token; the scorer must still recover the curl URLs so the
    # finding's evidence-body bundle inherits the right method/path.
    command = (
        "sh -c 'python3 - <<PY\n"
        "import base64,json\n"
        'h=base64.urlsafe_b64encode(json.dumps({"alg":"none"}).encode())\n'
        "PY\n"
        "curl -sS -i --http1.1 https://duck-store.escape.tech/api/v1/auth/me "
        '-H "Authorization: Bearer x" -o evidence/vuln-research/jwt-none-me.txt '
        '-w "HTTP %{http_code}\\n"\''
    )
    requests = _command_requests(command)
    urls = {str(request.url) for request in requests}
    assert "https://duck-store.escape.tech/api/v1/auth/me" in urls


def test_command_requests_resolves_shell_baseurl_variables() -> None:
    # `export B=...; curl $B/auth/login ...; curl $B/users/me/profile ...` puts
    # the URLs behind a shell variable. URL extraction must resolve $B so the
    # exploit request (not just the literal export assignment) is recovered.
    command = (
        "export B=https://duck-store.escape.tech/api/v1; "
        "ATOK=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' "
        '-d \'{"username":"tester","password":"pw"}\' | python3 -c \'import '
        'sys,json;print(json.load(sys.stdin)["access_token"])\'); '
        "curl -sS -i -X PUT $B/users/me/profile -H 'Authorization: Bearer ***' "
        '-d \'{"role":"admin"}\' -o evidence/vuln-research/massassign.txt'
    )
    requests = _command_requests(command)
    urls = {str(request.url) for request in requests}
    assert "https://duck-store.escape.tech/api/v1/users/me/profile" in urls


def test_command_requests_does_not_mutate_command_substitution() -> None:
    # ``$(...)`` is command substitution, not a variable reference: the opener
    # ``$`` is followed by ``(`` so it must not collapse into an env lookup.
    command = "echo $(whoami) && curl -sS -i https://example.test/api/items -w 'HTTP %{http_code}'"
    assert _command_requests(command)


def test_compound_login_command_body_does_not_inherit_login_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A body saved by the SECOND curl (the exploit) of a compound command that
    # first logs in must NOT be matched to the login endpoint (weak-admin-creds).
    # The shell-variable resolution must not leak `POST $B/auth/login` into the
    # saved body's requests.
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    command = (
        "export B=https://duck-store.escape.tech/api/v1; "
        "ATOK=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' "
        '-d \'{"username":"tester","password":"pw"}\'); '
        "curl -sS -i $B/testimonials/6 -o evidence/vuln-research/testimonial-6-read.txt "
        "-w 'HTTP %{http_code}'"
    )
    body_dir = tmp_path / "evidence" / "vuln-research"
    body_dir.mkdir(parents=True, exist_ok=True)
    body = body_dir / "testimonial-6-read.txt"
    body.write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
    body_relative = body.relative_to(tmp_path).as_posix()
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command=command,
        proof="HTTP/1.1 200 OK\n",
        declared_evidence_outputs=[body_relative],
    )
    golden_id, candidates = match_finding(
        tmp_path,
        {
            "receipt_paths": [receipt_path],
            "evidence_paths": [body_relative],
        },
        load_golden_set(),
        receipt_key=key,
    )
    assert "weak-admin-creds" not in candidates


def test_compound_command_body_correlates_to_its_own_subcommand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A body saved by the SECOND curl of a two-curl `sh -c` command must not
    # inherit the FIRST curl's method/path. Regression: user-enumeration body
    # was matched to mass-assign-role because it inherited the mass-assign PUT.
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    command = (
        "sh -c 'curl -sS -i --http1.1 -X PUT "
        "https://duck-store.escape.tech/api/v1/users/me/profile "
        '-H "Authorization: Bearer x" -d "{\\"role\\":\\"admin\\"}" '
        '-o evidence/vuln-research/profile-massassign.txt -w "HTTP %{http_code}\\n"; '
        "curl -sS -i --http1.1 https://duck-store.escape.tech/api/v1/users/ "
        '-o evidence/vuln-research/users-unauth-enum.txt -w "HTTP %{http_code}\\n"\''
    )
    # Save the user-enumeration body and attach it as evidence_paths.
    body_dir = tmp_path / "evidence" / "vuln-research"
    body_dir.mkdir(parents=True, exist_ok=True)
    body = body_dir / "users-unauth-enum.txt"
    body.write_text(
        'HTTP/1.1 200 OK\n{"users":[{"username":"alice"},{"username":"bob"}]}\n',
        encoding="utf-8",
    )
    body_relative = body.relative_to(tmp_path).as_posix()
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command=command,
        proof="HTTP/1.1 200 OK\n",
        declared_evidence_outputs=[body_relative],
    )
    finding = {
        "receipt_paths": [receipt_path],
        "evidence_paths": [body_relative],
    }
    golden_id, candidates = match_finding(
        tmp_path,
        finding,
        load_golden_set(),
        receipt_key=key,
    )
    assert golden_id == "user-enumeration", candidates
    assert "mass-assign-role" not in candidates


def test_agent_container_excludes_private_evaluator() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert "/violin/benchmark/private" in dockerfile
    assert "/violin/benchmark/proof.py" in dockerfile
    assert "/violin/benchmark/score.py" in dockerfile
    # Dev-only surfaces (tests/, docs/, .github/, AGENTS.md) are excluded by
    # whitelist COPY — the image never copies the whole repo, so unlisted
    # paths never ship (no rm -rf needed for them).
    assert "COPY . /violin/" not in dockerfile


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

    with pytest.raises(ValueError, match="authenticated by a cited execution receipt"):
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
