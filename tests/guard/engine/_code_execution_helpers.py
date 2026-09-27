"""Tests for Violin's execute_code audit and receipt persistence."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.hooks import (
    _post_tool_call_hook,
    _pre_tool_call_hook,
)
from tests.guard.receipt_fixture import bind_active_task

_SCOPE = """targets:
  ip_addresses: ["10.10.10.10"]
  in_scope_urls: []
exclusions: {}
authorized_parties: ["test owner"]
authorisation:
  confirmed: true
rules_of_engagement:
  allowed_actions: [recon]
  forbidden_actions: []
engagement:
  name: audit-test
  date: "2026-07-16"
  type: authorised-pentest
  client: test
"""


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    (eng / "scope" / "scope.yaml").write_text(_SCOPE, encoding="utf-8")
    (eng / "state" / ".skill-loaded-test").write_text("skill-loaded: test\n", encoding="utf-8")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "test")
    return eng


def _code(eng, target="10.10.10.10") -> str:
    return (
        '# violin: {"eng_dir":"'
        + str(eng).replace("\\", "\\\\")
        + '","phase":"RECON","target":"'
        + target
        + '","session_id":"test"}\n'
        "print('local audit work')\n"
    )


def _complete_execute_code_result(
    eng: Path,
    result: object,
    *,
    tool_call_id: str,
    source_suffix: str = "",
) -> tuple[Path, dict, dict, str]:
    source = _code(eng) + source_suffix
    manifests_before = set((eng / "evidence" / "executions").glob("*-execute-code.json"))
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id=tool_call_id,
        )
        is None
    )
    new_manifests = (
        set((eng / "evidence" / "executions").glob("*-execute-code.json")) - manifests_before
    )
    assert len(new_manifests) == 1
    manifest = new_manifests.pop()
    intent = json.loads(manifest.read_text(encoding="utf-8"))
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result=result,
        duration_ms=3,
        session_id="test",
        tool_call_id=tool_call_id,
    )
    completed = json.loads(manifest.read_text(encoding="utf-8"))
    return manifest, intent, completed, source


def _no_active_task_engagement(tmp_path: Path) -> Path:
    eng = _engagement(tmp_path)
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [~] |", "| PT-010 | [ ] |"),
        encoding="utf-8",
    )
    return eng
