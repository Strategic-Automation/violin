from __future__ import annotations

import json

from plugins.violin_guard import handlers as TOOLS
from plugins.violin_guard.core.engagement import ptt
from plugins.violin_guard.core.skills.skill_receipts import SkillViewResult
from plugins.violin_guard.gates import command
from plugins.violin_guard.handlers import ptt_handlers
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)
from tests.guard.integration.guard_fixture import (
    _init_e2e,
)


class _ReadySkillAdapter:
    def view(self, *_args, **_kwargs) -> SkillViewResult:
        return SkillViewResult(True, "skill")


def test_record_ptt_can_start_pristine_task(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ptt_handlers,
        "HermesSkillViewAdapter",
        _ReadySkillAdapter,
    )
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [~] |", "| PT-010 | [ ] |"),
        encoding="utf-8",
    )

    result = json.loads(
        TOOLS.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "Start recon",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert result["status"] == "skill_prepared", result
    result = json.loads(
        TOOLS.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "Start recon",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert result["status"] == "ok", result
    assert result["task_started"] is True
    assert ptt.find_active_task(ptt.parse_ptt(ptt_path)).id == "PT-010"


def test_first_command_requires_an_active_ptt_task(tmp_path):
    """The guard blocks target work until one PTT task is explicitly active."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [~] |", "| PT-010 | [ ] |"),
        encoding="utf-8",
    )

    args = command.CheckCommandArgs(
        command="nmap -sV 10.10.10.10",
        phase="recon",
        eng_dir=str(eng),
        scope=str(eng / "scope" / "scope.yaml"),
        session_id="ts",
    )
    first = command.check_command(args)

    assert any(
        "exactly one" in error.lower() or "active task" in error.lower() for error in first.errors
    )


def test_multiple_active_ptt_tasks_block_target_execution(tmp_path):
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-011 | [ ] |", "| PT-011 | [~] |"),
        encoding="utf-8",
    )
    result = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="recon",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert any(
        "exactly one" in error.lower() or "active task" in error.lower() for error in result.errors
    )
