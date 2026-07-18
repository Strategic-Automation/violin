"""Regression coverage for the guard workflow ergonomics fixes (A1-A15)."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard import (
    bootstrap,
    command,
    execution,
    hypotheses,
    ptt,
    service,
    state,
)
from plugins.violin_guard.command import CheckCommandArgs, CheckResult, check_scope_authorization
from plugins.violin_guard.history import append_history, check_history_staleness
from plugins.violin_guard.phases import Phase
from plugins.violin_guard.skill_receipts import SkillViewResult
from plugins.violin_guard.targets import check_scope_targets


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "eng"
    assert bootstrap.init_engagement(str(eng), host="10.10.10.10") == 0
    scope = eng / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8").replace(
            "allowed_actions: []", "allowed_actions: [recon]"
        ),
        encoding="utf-8",
    )
    (eng / "state" / ".skill-loaded-current").write_text("ok\n", encoding="utf-8")
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    return eng


def test_command_defaults_scope_and_single_skill_session_from_engagement(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    result = command.check_command(
        CheckCommandArgs(command="echo safe", phase="recon", eng_dir=str(eng), target="10.10.10.10")
    )
    assert not any("session_id is required" in error for error in result.errors)
    assert not any("scope file not found" in error for error in result.errors)
    assert any("sync credit remaining" in info for info in result.infos)


def test_wildcard_scope_allows_subdomains(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text("targets:\n  domains: ['*.example.test']\n", encoding="utf-8")
    assert not check_scope_targets(
        scope, "curl https://api.example.test", "api.example.test"
    ).errors


def test_ptt_heading_parenthetical_and_explicit_task_create_close(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        service,
        "HermesSkillViewAdapter",
        lambda: type("Ready", (), {"view": lambda *_a, **_k: SkillViewResult(True, "skill")})(),
    )
    eng = _engagement(tmp_path)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace(
            "## Phase: RECON", "## Phase: RECON (web enumeration)"
        ),
        encoding="utf-8",
    )
    assert ptt.find_active_task(ptt.parse_ptt(ptt_path)).phase == "RECON"
    created = json.loads(
        service.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-900",
                "status": "[ ]",
                "title": "extra check",
                "phase": "recon",
                "note": "planned",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert created["status"] == "skill_prepared"
    created = json.loads(
        service.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-900",
                "status": "[ ]",
                "title": "extra check",
                "phase": "recon",
                "note": "planned",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert created["task_created"] is True
    # A fresh session must prepare again; do not rely on cross-task reuse here.
    state.record_session_id(eng, "close-session")
    close_args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[x]",
        "note": "done",
        "skill": "pentest",
        "technique": "recon",
    }
    closed = json.loads(service.handle_record_ptt(close_args))
    assert closed["status"] == "skill_prepared"
    closed = json.loads(service.handle_record_ptt(close_args))
    assert closed["task_closed"] is True


def test_hypothesis_free_form_record_gets_an_id_and_parenthetical_target(tmp_path: Path) -> None:
    record = hypotheses.update_hypothesis(
        tmp_path / "hypotheses.md",
        in_scope_hosts={"api.example.test"},
        title="API auth",
        target="api.example.test (login)",
        rationale="free-form operator note",
    )
    assert record.id == "001"
    assert record.target == "api.example.test (login)"


def test_allowed_actions_error_names_the_expected_terms() -> None:
    result = check_scope_authorization(
        {"rules_of_engagement": {"allowed_actions": ["reporting"]}}, Phase.RECON
    )
    assert "recon" in result.errors[0]
    assert "one of:" in result.errors[0]


def test_pending_batch_repeat_is_allowed_for_recovery(tmp_path: Path) -> None:
    append_history(tmp_path, "nmap -sV 10.10.10.10", "RECON", 0)
    errors, _, infos = check_history_staleness(
        tmp_path, "nmap -sV 10.10.10.10", allow_pending_repeat=True
    )
    assert not errors
    assert any("pending batch" in info for info in infos)


def test_burst_continues_past_review_required_command(tmp_path: Path, monkeypatch) -> None:
    eng = _engagement(tmp_path)
    checks = iter((CheckResult(warnings=["review first"]), CheckResult()))
    monkeypatch.setattr(service, "_check_command_internal", lambda _args: next(checks))
    executed: list[str] = []

    def fake_execute(command: str, **_kwargs):
        executed.append(command)
        return {"executed": True, "exit_code": 0, "status": "completed"}

    monkeypatch.setattr(execution, "execute", fake_execute)
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "phase": "recon",
                "target": "10.10.10.10",
                "commands": ["first", "second"],
            }
        )
    )
    assert data["status"] == "batch_complete"
    assert data["review_required"] is True
    assert executed == ["first", "second"]
