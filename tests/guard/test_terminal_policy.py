"""Regression tests for Violin's raw-terminal policy."""

from __future__ import annotations

import pytest

from plugins.violin_guard import (
    _on_session_reset_hook,
    _post_tool_call_hook,
    _pre_llm_call_hook,
    _pre_tool_call_hook,
    bootstrap,
    register,
)
from plugins.violin_guard import command as guard_command
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

    def register_tool(self, **_kwargs) -> None:
        pass

    def register_hook(self, name: str, callback) -> None:
        self.hooks[name] = callback


def test_plugin_registers_terminal_policy_hook() -> None:
    context = _Context()
    register(context)
    assert context.hooks["pre_tool_call"] is _pre_tool_call_hook
    assert context.hooks["post_tool_call"] is _post_tool_call_hook


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


def test_local_source_retrieval_remains_available() -> None:
    result = _pre_tool_call_hook(
        tool_name="terminal",
        args={"command": "git clone https://github.com/example/project.git"},
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


def test_local_script_paths_are_not_treated_as_hosts() -> None:
    assert (
        _pre_tool_call_hook(tool_name="terminal", args={"command": "python scripts/setup.py"})
        is None
    )
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": "bash ./run.py"}) is None
    assert _pre_tool_call_hook(tool_name="terminal", args={"command": "sh deploy.sh"}) is None


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
        (
            "python3 scripts/violin_guard.py init-engagement "
            '--host "$TARGET" "$ENG_DIR"'
        ),
        (
            "python3 scripts/violin_guard.py init-engagement "
            '--host=`cat /tmp/target` "$ENG_DIR"'
        ),
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


def test_target_tools_require_an_engagement_binding() -> None:
    result = _pre_tool_call_hook(
        tool_name="violin_exec",
        args={"command": "nmap -sV 10.10.10.10"},
        session_id="test-session",
    )

    assert result["action"] == "block"
    assert "engagement associated" in result["message"]


def test_skill_delivery_turn_blocks_target_and_browser_until_next_turn(tmp_path) -> None:
    eng = _engagement(tmp_path)
    _pre_llm_call_hook(session_id="test", eng_dir=str(eng))
    _post_tool_call_hook(
        tool_name="violin_record_ptt",
        args={"eng_dir": str(eng), "id": "PT-010"},
        result='{"status":"ok","task_id":"PT-010"}',
        turn_id="turn-bind",
    )

    blocked = _pre_tool_call_hook(
        tool_name="violin_exec",
        args={"eng_dir": str(eng), "session_id": "test"},
        session_id="test",
        turn_id="turn-bind",
    )
    assert blocked["action"] == "block"
    assert "next turn" in blocked["message"]

    browser_blocked = _pre_tool_call_hook(
        tool_name="browser_navigate",
        args={"url": "https://10.10.10.10"},
        session_id="test",
        turn_id="turn-bind",
    )
    assert browser_blocked["action"] == "block"

    assert (
        _pre_tool_call_hook(
            tool_name="browser_navigate",
            args={"url": "https://10.10.10.10"},
            session_id="test",
            turn_id="turn-next",
        )
        is None
    )


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
        tool_name="execute_code", args={"code": "print('missing header')"}
    )
    assert blocked["action"] == "block"
    assert "first-line metadata" in blocked["message"]

    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": _code(_engagement(tmp_path), "10.10.10.11")}
    )
    assert blocked["action"] == "block"
    assert "Violin guard" in blocked["message"]


def test_execute_code_is_validated_and_recorded(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng)
    assert _pre_tool_call_hook(tool_name="execute_code", args={"code": source}) is None

    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"result":"ok"}',
        duration_ms=42,
    )

    receipts = list((eng / "evidence" / "recon").glob("execute-code-*.py"))
    assert len(receipts) == 1
    assert receipts[0].read_text(encoding="utf-8") == source
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "execute_code sha256=" in history
    assert "status=ok" in history
    assert "exit_code=0" in history


def test_execute_code_records_tool_errors(tmp_path) -> None:
    eng = _engagement(tmp_path)
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": _code(eng)},
        result='{"error":"sandbox failed"}',
        duration_ms=7,
    )
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "status=error" in history
    assert "exit_code=1" in history
