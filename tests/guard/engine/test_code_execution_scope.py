"""Tests for Violin's execute_code audit and receipt persistence."""

from __future__ import annotations

from plugins.violin_guard.hooks import (
    _pre_tool_call_hook,
)
from tests.guard.engine._code_execution_helpers import (
    _code,
    _engagement,
)


def test_execute_code_rejects_foreign_literal_target(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "url = 'https://10.10.10.11/admin'\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": source}, tool_call_id="foreign-target"
    )
    assert blocked["action"] == "block"
    assert "differ from declared target" in blocked["message"]


def test_execute_code_local_find_paths_are_not_foreign_targets(tmp_path) -> None:
    """Local evidence path strings in code must not be flagged as foreign targets."""
    eng = _engagement(tmp_path)
    source = _code(eng) + (
        "local_files = ['evidence/findings.jsonl', 'state/hypotheses.md']\n"
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


def test_execute_code_dom_api_pattern_text_is_not_a_foreign_target(tmp_path) -> None:
    """Identifier-shaped pattern text must not read as a target literal (#178)."""
    eng = _engagement(tmp_path)
    source = _code(eng) + (
        "bundle = open('evidence/executions/app.js', encoding='utf-8').read()\n"
        "for sink in ['window.location', 'document.location', 'location.href']:\n"
        "    print(sink, bundle.count(sink))\n"
    )
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="dom-api",
        )
        is None
    )


def test_execute_code_rejects_a_bare_foreign_ip_literal(tmp_path) -> None:
    """The endpoint rule must still refuse an out-of-scope address literal."""
    eng = _engagement(tmp_path)
    source = _code(eng) + "host = '10.10.10.11'\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": source}, tool_call_id="bare-ip"
    )
    assert blocked["action"] == "block"
    assert "differ from declared target" in blocked["message"]


def test_execute_code_punctuation_literals_are_not_foreign_targets(tmp_path) -> None:
    """A separator string is not a network target (#220).

    "::" parses as the IPv6 unspecified address, so a log separator used to be
    treated as an out-of-scope target and block an in-scope script.
    """
    eng = _engagement(tmp_path)
    source = _code(eng) + "separator = '::'\nprint('host 10 ' + separator + ' port 80')\n"
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="punctuation-separator",
        )
        is None
    )


def test_execute_code_still_rejects_a_foreign_ipv6_literal(tmp_path) -> None:
    """Skipping punctuation must not weaken detection of a real address (#220)."""
    eng = _engagement(tmp_path)
    source = _code(eng) + "peer = 'fe80::1'\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        tool_call_id="foreign-ipv6",
    )
    assert blocked["action"] == "block"
    assert "differ from declared target" in blocked["message"]


def test_execute_code_foreign_literal_error_names_the_line(tmp_path) -> None:
    """The rejection must locate the offending literal, not just name it (#220)."""
    eng = _engagement(tmp_path)
    source = _code(eng) + "first = 1\nsecond = 2\nhost = '10.10.10.11'\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        tool_call_id="literal-line",
    )
    assert blocked["action"] == "block"
    assert "10.10.10.11 (line " in blocked["message"]


def test_execute_code_extra_header_key_names_the_key(tmp_path) -> None:
    """An invented header key is reported as such, not as a missing header (#220)."""
    eng_dir = str(_engagement(tmp_path)).replace("\\", "/")
    code = f'# violin: {{"eng_dir":"{eng_dir}","phase":"recon","target":"10.10.10.10"}}\nprint(1)'
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": code}, tool_call_id="extra-header-key"
    )
    assert blocked["action"] == "block"
    assert "unexpected key(s): 'target'" in blocked["message"]
