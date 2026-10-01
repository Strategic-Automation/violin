"""Burst execution regression tests."""

import json

import pytest

from plugins.violin_guard import handlers as service
from plugins.violin_guard.core import schemas
from plugins.violin_guard.core.engagement import bootstrap, state
from plugins.violin_guard.engine import execution
from plugins.violin_guard.gates.command import CheckResult
from tests.guard.handlers._burst_helpers import (
    _SCOPE,
    _patch_burst,
)
from tests.guard.handlers._burst_helpers import (
    eng as eng,
)
from tests.guard.receipt_fixture import bind_active_task


def test_exec_burst_clean_review_or_approved(eng, monkeypatch):
    """A batch of in-scope recon commands passes the gate (batch_complete, no
    DENIED) and arms a single pending-sync lock."""
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": [
                    "nmap -sV 10.10.10.10",
                    "gobuster dir -u http://10.10.10.10",
                ],
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "recon-batch",
            }
        )
    )
    assert data["status"] == "batch_complete", data
    assert data["executed"] == 2, data
    assert len(rec["commands"]) == 2
    # Only the LAST command arms the gate -> exactly one pending-sync lock.
    assert state.has_pending_sync(str(eng)) is not None


@pytest.mark.parametrize(
    ("secondary_only_host", "expected_reason"),
    [
        ("listener.example", "secondary-only endpoint"),
        (
            "github.com",
            "research_hosts may be explicit execution targets only during VULN_RESEARCH",
        ),
    ],
)
def test_exec_burst_denies_secondary_only_primary_target(
    eng, monkeypatch, secondary_only_host, expected_reason
):
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": [f"curl https://{secondary_only_host}"],
                "target": secondary_only_host,
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "secondary-only-primary",
            }
        )
    )

    assert data["status"] == "denied"
    assert data["executed"] == 0
    assert expected_reason in data["reason"]
    assert rec["commands"] == []


def test_exec_burst_fail_closed_on_blocked_command(eng, monkeypatch):
    """A batch containing a hard-blocked command (e.g. `rm -rf /`) is denied
    and the batch is halted at the first BLOCK (fail-closed)."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": [
                    "nmap -sV 10.10.10.10",
                    "rm -rf /",
                ],
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "bad-batch",
            }
        )
    )
    assert data["status"] == "denied", data
    assert (
        data["reason"] == "command [2] blocked: destructive filesystem deletion (rm -rf) is blocked"
    ), data
    # Preflight is atomic: the blocked command prevents every command from launching.
    assert rec["commands"] == []


def test_exec_burst_preflights_every_command_before_launch(eng, monkeypatch):
    from plugins.violin_guard.handlers import exec_handlers

    checks = iter((CheckResult(), CheckResult(errors=["blocked second command"])))
    launched: list[str] = []
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda _args: next(checks))
    monkeypatch.setattr(execution, "execute", lambda command, **_kwargs: launched.append(command))

    before = state.sync_credit_remaining(eng, "recon")
    result = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "phase": "recon",
                "target": "10.10.10.10",
                "commands": ["first", "second"],
            }
        )
    )

    assert result["status"] == "denied"
    assert result["executed"] == 0
    assert launched == []
    assert state.sync_credit_remaining(eng, "recon") == before


def test_plugin_exec_burst_accepts_inline_commands(monkeypatch, tmp_path):
    """In-process handle_exec_burst with a monkeypatched executor runs every
    inline command and reports batch_complete without a real network call."""
    d = tmp_path / "10.10.10.10-2026-07-08"
    assert bootstrap.init_engagement(str(d), host="10.10.10.10") == 0
    (d / "scope" / "scope.yaml").write_text(_SCOPE, encoding="utf-8")
    (d / "state" / ".skill-loaded-ts").write_text(
        "skill-loaded: skills/pentest/SKILL.md\nsession: ts\n", encoding="utf-8"
    )
    ptt = d / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(d, "ts")
    _patch_burst(monkeypatch, str(d))
    raw = service.handle_exec_burst(
        {
            "eng_dir": str(d),
            "scope": str(d / "scope" / "scope.yaml"),
            "phase": "recon",
            "commands": [
                "gobuster dir -u http://10.10.10.10 -H 'Host: nimbus.htb' -w /usr/share/wordlists/dirb/common.txt",
                "curl -H 'Host: nimbus.htb' http://10.10.10.10/",
            ],
            "session_id": "ts",
            "skill_loaded_file": str(d / "state" / ".skill-loaded-ts"),
            "label": "recon-batch",
        }
    )
    data = json.loads(raw)
    assert data["status"] == "batch_complete"
    assert data["executed"] == 2
    assert len(data["results"]) == 2
    assert [item["index"] for item in data["results"]] == [1, 2]
    assert "gobuster dir" in data["results"][0]["command"]
    assert "curl -H" in data["results"][1]["command"]


def test_exec_burst_model_accepts_evidence_outputs():
    """A burst may declare the evidence files it writes, like violin_exec does."""
    model = schemas.ExecBurstArgsModel(
        eng_dir="eng",
        phase="recon",
        target="10.10.10.10",
        commands=["curl -i http://10.10.10.10/"],
        evidence_outputs=["evidence/recon/root.txt"],
    )

    assert model.evidence_outputs == ["evidence/recon/root.txt"]


def test_exec_burst_declares_evidence_outputs_on_every_command_receipt(eng, monkeypatch):
    """Burst-declared evidence must reach each receipt so findings can cite it.

    Bursts are approved as one batch, so the declared outputs apply to every
    command in it; without this, files written by a burst cannot authenticate a
    finding and violin_submit_finding rejects the citation.
    """
    _patch_burst(monkeypatch, str(eng))
    declared = [
        "evidence/vuln-research/ratelimit_login.txt",
        "evidence/recon/login_admin.txt",
    ]
    captured: list[list[str]] = []
    inner_execute = execution.execute

    def recording_execute(command, **kwargs):
        captured.append(list(kwargs.get("evidence_outputs") or []))
        return inner_execute(command, **kwargs)

    monkeypatch.setattr(execution, "execute", recording_execute)
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "target": "10.10.10.10",
                "commands": [
                    "curl -i http://10.10.10.10/api/v1/users/ -o evidence/recon/login_admin.txt",
                    "nmap -sV 10.10.10.10",
                ],
                "evidence_outputs": declared,
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "evidence-batch",
            }
        )
    )

    assert data["status"] == "batch_complete", data
    assert captured == [declared, declared]
