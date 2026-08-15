from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest

from plugins.violin_guard import bootstrap, command, hypotheses, ptt, state
from plugins.violin_guard.command import check_scope_authorization, validate_scope
from plugins.violin_guard.handlers.ptt_handlers import (
    _redact_sensitive_note,
    _start_ptt_task,
    _validate_phase_exit,
)
from plugins.violin_guard.phases import Phase


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


def test_reporting_exit_requires_canonical_finding(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
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
    with pytest.raises(ValueError, match="canonical findings: H-001"):
        _validate_phase_exit(engagement, "PT-050", "[x]")


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


def test_reporting_exit_allows_exploitation_history_in_audit_mode(tmp_path: Path) -> None:
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
    # No exploitation-phase-history error: the run reached EXPLOITATION. It
    # still blocks on the unlinked Validated hypothesis (no FIND file yet).
    with pytest.raises(ValueError, match="canonical findings: H-001"):
        _validate_phase_exit(engagement, "PT-050", "[x]")


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


def test_vuln_research_exit_blocks_validated_hypothesis_without_linked_finding(
    tmp_path: Path,
) -> None:
    """Scorer-confirmed contract: Validated hypotheses must link FIND files."""
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
    proof = engagement / "evidence" / "vuln-research" / "admin_users.txt"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("200 with admin data\n", encoding="utf-8")
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Admin ACL bypass",
        status="Validated",
        test_response="200 with admin data",
        runtime_evidence="evidence/vuln-research/admin_users.txt",
    )
    with pytest.raises(ValueError, match="every Validated hypothesis links a canonical"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_accepts_validated_hypothesis_with_linked_finding(
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
    finding_dir = engagement / "evidence" / "findings"
    finding_dir.mkdir(parents=True, exist_ok=True)
    finding_dir.joinpath("FIND-001.md").write_text(
        "# FIND-001: Admin ACL bypass\n- **Key:** value\n", encoding="utf-8"
    )
    proof = engagement / "evidence" / "vuln-research" / "admin_users.txt"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("200 with admin data\n", encoding="utf-8")
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Admin ACL bypass",
        status="Validated",
        test_response="200 with admin data",
        runtime_evidence="evidence/vuln-research/admin_users.txt",
        linked_findings="FIND-001",
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
