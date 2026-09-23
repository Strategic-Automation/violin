from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path

import pytest
import yaml

from plugins.violin_guard.core import (
    bootstrap,
    findings,
    history,
    hypotheses,
    ptt,
    receipt_integrity,
    state,
)
from plugins.violin_guard.core.phases import Phase
from plugins.violin_guard.gates import command
from plugins.violin_guard.gates.command import check_scope_authorization, validate_scope
from plugins.violin_guard.handlers.ptt_gates import (
    _coverage_key_errors,
    _methodology_gate_errors,
    _redact_sensitive_note,
    _validate_phase_exit,
)
from plugins.violin_guard.handlers.ptt_handlers import _start_ptt_task


def _scope(tmp_path: Path, targets: str, allowed: str = "recon") -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        f"""targets:
  {targets}
rules_of_engagement:
  allowed_actions: [{allowed}]
  forbidden_actions: []
engagement:
  date: 2026-08-01
authorized_parties: [operator]
authorisation:
  confirmed: true
""",
        encoding="utf-8",
    )
    return path


def test_domain_only_scope_is_valid(tmp_path: Path) -> None:
    result = validate_scope(_scope(tmp_path, "domains: [app.example.test]"))
    assert not any("ip_addresses" in error for error in result.errors)
    assert not result.errors


def test_url_only_scope_is_valid(tmp_path: Path) -> None:
    result = validate_scope(_scope(tmp_path, "urls: [https://app.example.test/login]"))
    assert not result.errors


def test_exploitation_is_not_blocked_by_post_exploitation_forbidden_action() -> None:
    result = check_scope_authorization(
        {
            "rules_of_engagement": {
                "allowed_actions": ["exploitation"],
                "forbidden_actions": ["post-exploitation"],
            }
        },
        Phase.EXPLOITATION,
    )
    assert not result.errors


def test_scope_actions_reject_negations_and_containing_phrases() -> None:
    for value in ("no exploitation", "post-exploitation", "pre-exploitation-check"):
        result = check_scope_authorization(
            {
                "rules_of_engagement": {
                    "allowed_actions": [value],
                    "forbidden_actions": [],
                }
            },
            Phase.EXPLOITATION,
        )
        assert result.errors, value


def test_credential_stuffing_does_not_match_hydra_by_substring() -> None:
    result = check_scope_authorization(
        {
            "rules_of_engagement": {
                "allowed_actions": ["recon"],
                "forbidden_actions": ["credential-stuffing"],
            }
        },
        Phase.RECON,
    )
    assert not any("forbidden" in error for error in result.errors)


def test_runtime_command_rejects_scope_substitution(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    result = command.check_command(
        command.CheckCommandArgs(
            command="echo local",
            phase="recon",
            eng_dir=str(engagement),
            scope=str(tmp_path / "other-scope.yaml"),
            target="10.10.10.10",
        )
    )
    assert any("canonical scope.yaml" in error for error in result.errors)


def test_command_scope_diagnostic_uses_canonical_path_without_mutation(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope_path = engagement / "scope" / "scope.yaml"
    original_scope = scope_path.read_bytes()

    result = command.check_command(
        command.CheckCommandArgs(
            command="curl https://outside.example/status",
            phase="recon",
            eng_dir=str(engagement),
            target="10.10.10.10",
        )
    )

    assert any(str(scope_path.resolve()) in warning for warning in result.warnings)
    assert scope_path.read_bytes() == original_scope


def test_multi_task_ptt_update_validates_before_atomic_replace(tmp_path: Path) -> None:
    path = tmp_path / "ptt.md"
    path.write_text(
        "## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-001 | [~] | Active | original |\n"
        "| PT-002 | [ ] | Next | untouched |\n",
        encoding="utf-8",
    )
    original = path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="PT-999"):
        ptt.update_tasks(path, {"PT-001": ("[x]", "done"), "PT-999": ("[~]", "bad")})
    assert path.read_text(encoding="utf-8") == original


def test_concurrent_ptt_transitions_are_serialized_by_workflow_lock(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    ptt_path = engagement / "state" / "ptt.md"

    def start(task_id: str) -> None:
        with state.workflow_lock(engagement):
            tasks = ptt.parse_ptt(ptt_path)
            _start_ptt_task(
                ptt_path,
                tasks,
                task_id,
                "[~]",
                f"started {task_id}",
                eng_dir=engagement,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(start, ("PT-010", "PT-011")))

    tasks = ptt.parse_ptt(ptt_path)
    assert len([task for task in tasks if task.status == "[~]"]) == 1
    assert {task.id for task in tasks} >= {"PT-010", "PT-011"}


def test_vulnerability_research_exit_blocks_unresolved_hypotheses(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md", id="001", title="Unresolved", status="Likely"
    )
    with pytest.raises(ValueError, match="unresolved hypotheses: H-001"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_ptt_notes_redact_credentials_before_persisting() -> None:
    note = (
        "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature "
        "Authorization: Bearer bearer-secret "
        "key sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789"
    )
    redacted = _redact_sensitive_note(note)
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    assert "bearer-secret" not in redacted
    assert "sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "[REDACTED_JWT]" in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "[REDACTED_API_KEY]" in redacted


def test_audit_mode_vulnerability_research_exit_requires_dispositioned_matrix(
    tmp_path: Path,
) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: pending\n    evidence_or_reason: ''\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="undispositioned coverage: routes"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


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


def test_bootstrap_pre_keys_the_coverage_matrix_from_declared_obligations(
    tmp_path: Path,
) -> None:
    """#123: a bootstrapped engagement starts from its real obligation keys, not placeholders."""
    engagement = tmp_path / "engagement"
    scope_path = engagement / "scope" / "scope.yaml"
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text(
        yaml.safe_dump(
            {
                "targets": {"ip_addresses": ["10.10.10.10"], "in_scope_urls": []},
                "rules_of_engagement": {"allowed_actions": ["recon"], "forbidden_actions": []},
                "engagement": {
                    "coverage_obligations": ["POST /api/v1/auth/login", "GET /api/users"]
                },
                "authorisation": {"confirmed": True},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0

    matrix = yaml.safe_load(
        (engagement / "state" / "coverage-matrix.yaml").read_text(encoding="utf-8")
    )
    coverage = matrix["coverage"]
    assert set(coverage) == {"post /api/v1/auth/login", "get /api/users"}
    assert {cell["status"] for cell in coverage.values()} == {"pending"}


def test_seeded_coverage_keys_match_the_close_gate_vocabulary() -> None:
    """#123: the writer (bootstrap) and the reader (close gate) agree on the keys, and an
    unrecognised key names the accepted vocabulary instead of surfacing at close."""
    obligations = ["POST /api/v1/auth/login"]
    seeded = {"post /api/v1/auth/login": {"status": "pending", "evidence_or_reason": ""}}
    assert _coverage_key_errors(seeded, obligations) == []

    errors = _coverage_key_errors(
        {"post /api/v1/auth/other": {"status": "pending", "evidence_or_reason": ""}},
        obligations,
    )
    assert errors and "accepted keys: post /api/v1/auth/login" in errors[0]


def test_vuln_research_exit_requires_evidence_for_not_applicable_coverage(
    tmp_path: Path,
) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n"
        "  rate_limits:\n"
        "    status: not_applicable\n"
        "    evidence_or_reason: 'no rate-limit behavior observed on target'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not_applicable without evidence file"):
        _validate_phase_exit(engagement, "PT-030", "[x]")



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



def test_bootstrap_creates_coverage_matrix_template(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    matrix = engagement / "state" / "coverage-matrix.yaml"
    assert matrix.is_file()
    text = matrix.read_text(encoding="utf-8")
    assert "coverage:" in text
    assert "status:" in text
    assert "evidence_or_reason:" in text


def test_coverage_close_error_prints_exact_key_and_example(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    post_api_v1_auth_login:\n"
        "      status: tested\n      evidence_or_reason: 'evidence/x.txt'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        _validate_phase_exit(engagement, "PT-030", "[x]")
    msg = str(exc.value)
    assert "post /api/v1/auth/login" in msg  # names the first missing obligation
    assert "exact lowercased obligation" in msg.lower()  # key-format rule
    assert "status: tested" in msg  # example cell shown


def test_bootstrap_creates_methodology_gates_template(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    gates = engagement / "state" / "methodology-gates.yaml"
    assert gates.is_file()
    text = gates.read_text(encoding="utf-8")
    assert "gates:" in text
    assert "authentication-session" in text
    assert "evidence_or_reason:" in text


def _valid_gates_yaml() -> str:
    cells = "\n".join(
        f"  {g}:\n    status: tested\n    evidence_or_reason: 'evidence/vuln-research/{g}.txt probe'"
        for g in (
            "information-gathering",
            "configuration-deployment",
            "authentication-session",
            "authorization",
            "input-validation",
            "error-handling",
            "cryptography",
            "business-logic",
            "client-side",
            "api-testing",
        )
    )
    return f"gates:\n{cells}\n"


def test_methodology_gates_required_when_flag_set(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.unlink()  # simulate the agent never creating it
    with pytest.raises(ValueError, match="methodology-gates.yaml exists"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_methodology_gates_accepts_dispositioned_gates(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.write_text(_valid_gates_yaml(), encoding="utf-8")
    assert not _methodology_gate_errors(
        engagement, yaml.safe_load(scope.read_text(encoding="utf-8"))
    )


def test_methodology_gates_rejects_missing_categories(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.write_text(
        "gates:\n  authentication-session:\n    status: tested\n    evidence_or_reason: 'evidence/x.txt'\n",
        encoding="utf-8",
    )
    errors = _methodology_gate_errors(engagement, yaml.safe_load(scope.read_text(encoding="utf-8")))
    assert any("undispositioned methodology gates" in err for err in errors)


def test_methodology_gates_rejects_test_without_evidence(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.write_text(
        _valid_gates_yaml().replace("'evidence/vuln-research/", "'not-an-artifact/"),
        encoding="utf-8",
    )
    errors = _methodology_gate_errors(engagement, yaml.safe_load(scope.read_text(encoding="utf-8")))
    assert any("tested without evidence" in err for err in errors)


def test_vuln_research_exit_batches_all_preconditions_in_one_error(tmp_path: Path) -> None:
    """The close gate must surface methodology, coverage, AND hypothesis failures
    together — not one at a time — so the agent fixes them in a single pass."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n"
        "  coverage_obligations:\n    - POST /api/route_a\n",
        encoding="utf-8",
    )
    # 1. methodology-gates file missing
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.unlink()
    # 2. coverage matrix has a bad cell (status outside the vocabulary)
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  route_a:\n    status: pending\n    evidence_or_reason: ''\n",
        encoding="utf-8",
    )
    # 3. an unresolved hypothesis
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md", id="001", title="Unresolved", status="Likely"
    )
    with pytest.raises(ValueError) as exc:
        _validate_phase_exit(engagement, "PT-030", "[x]")
    msg = str(exc.value)
    # All three preconditions appear in the SAME error.
    assert "methodology-gates.yaml exists" in msg
    assert "undispositioned coverage" in msg
    assert "unresolved hypotheses: H-001" in msg


def test_vuln_research_coverage_error_teaches_remediation(tmp_path: Path) -> None:
    """The undispositioned-coverage error must name a fix, not just list failures."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - POST /api/route_a\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  route_a:\n    status: tested\n    evidence_or_reason: 'no artifact cited'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        _validate_phase_exit(engagement, "PT-030", "[x]")
    msg = str(exc.value)
    assert "coverage-matrix cell" in msg  # which obligation never got a cell
    assert "how to fix" in msg  # the gate teaches the remediation
    assert "'not_applicable' cells" in msg


def test_vuln_research_exit_accepts_evidence_backed_not_applicable(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n"
        "  rate_limits:\n"
        "    status: not_applicable\n"
        "    evidence_or_reason: 'probed 10x in evidence/recon/rate_probe.txt; no 429'\n",
        encoding="utf-8",
    )
    _validate_phase_exit(engagement, "PT-030", "[x]")  # no exception


def test_vuln_research_exit_blocks_not_implemented_rejection_without_evidence(
    tmp_path: Path,
) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: tested\n    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Admin login check",
        status="Rejected",
        verification_status="not_implemented",
        test_command="N/A - placeholder hypothesis",
        test_response="never executed",
        rejection_reason="placeholder superseded",
        cheapest_test="Login as admin (admin/admin)",
    )
    with pytest.raises(
        ValueError, match="rejections that never ran their cheapest discriminating test"
    ):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_accepts_surface_mapping_rejection_with_evidence(
    tmp_path: Path,
) -> None:
    """Known-good pattern: a recon surface-mapping hypothesis rejected as
    not_implemented is fine when it cites real bundle/probe evidence."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: tested\n    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="API surface enumeration from JS bundle",
        status="Rejected",
        verification_status="not_implemented",
        test_command="GET /api/v1/products/, /testimonials/",
        test_response="surface mapped, see evidence",
        rejection_reason="not a vulnerability claim",
        evidence="evidence/recon/recon_bundle.js",
        cheapest_test="Probe each derived endpoint",
    )
    _validate_phase_exit(engagement, "PT-030", "[x]")  # no exception


def test_validated_hypothesis_rejects_escaping_or_empty_evidence(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    board = engagement / "hypotheses.md"
    hypotheses.update_hypothesis(board, id="001", title="Candidate", status="Candidate")
    original = board.read_text(encoding="utf-8")
    outside = engagement / "outside.txt"
    outside.write_text("proof\n", encoding="utf-8")
    with pytest.raises(ValueError, match="beneath evidence"):
        hypotheses.update_hypothesis(
            board,
            id="001",
            status="Validated",
            runtime_evidence="evidence/../outside.txt",
        )
    assert board.read_text(encoding="utf-8") == original

    empty = engagement / "evidence" / "exploitation" / "empty.txt"
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="must not be empty"):
        hypotheses.update_hypothesis(
            board,
            id="001",
            status="Validated",
            runtime_evidence="evidence/exploitation/empty.txt",
        )


def test_validated_hypothesis_accepts_multiple_runtime_evidence_files(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    board = engagement / "hypotheses.md"
    for filename in ("request.txt", "response.txt"):
        path = engagement / "evidence" / "vuln-research" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("proof\n", encoding="utf-8")

    updated = hypotheses.update_hypothesis(
        board,
        id="001",
        title="Two-artifact proof",
        status="Validated",
        runtime_evidence=(
            "evidence/vuln-research/request.txt, evidence/vuln-research/response.txt"
        ),
    )

    assert updated.runtime_evidence.endswith("evidence/vuln-research/response.txt")


def test_vuln_research_exit_blocks_uncharted_scored_challenges(tmp_path: Path) -> None:
    """Coverage completeness: every in-scope endpoint needs a matrix cell.

    Client-provided in-scope endpoints (fetch-url, login) must map to a
    coverage-matrix cell — self-declared 'tested'/N/A coverage of related
    categories is not enough.
    """
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - GET /api/v1/uploads/fetch-url\n    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: tested\n    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no coverage-matrix cell"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_blocks_aspirational_tested_narrative(tmp_path: Path) -> None:
    """'tested' without an artifact reference is aspirational, not proof."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  redirects:\n    status: tested\n    evidence_or_reason: 'no open redirect parameter found'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="tested without evidence/FIND/hypothesis"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_accepts_challenge_cells_with_artifact(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  no-rate-limiting:\n    status: not_applicable\n    evidence_or_reason: 'evidence/vuln-research/rate_na.txt - 429 never observed; POST /api/v1/auth/login probed 20x'\n",
        encoding="utf-8",
    )
    _validate_phase_exit(engagement, "PT-030", "[x]")  # no exception
