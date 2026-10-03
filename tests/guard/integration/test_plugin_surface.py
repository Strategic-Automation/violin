from __future__ import annotations

from plugins.violin_guard import handlers as TOOLS
from plugins.violin_guard.core.commands.targets import extract_target_candidates
from plugins.violin_guard.gates import command
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)


def test_meta_loaded():
    # Current plugin surface: handle_* command entrypoints registered.
    for name in (
        "handle_exec",
        "handle_review_batch",
        "handle_record_ptt",
        "handle_record_hypothesis",
        "handle_submit_finding",
        "handle_exec_burst",
    ):
        assert hasattr(TOOLS, name), f"plugin must expose {name}"
    for removed in (
        "handle_sync_done",
        "handle_review_and_release",
        "handle_finding",
        "handle_check_command",
        "handle_ffuf",
        "handle_httpx",
        "handle_nuclei",
        "handle_listener",
        "handle_search_exploit",
    ):
        assert not hasattr(TOOLS, removed), f"plugin must not expose removed handler {removed}"


def test_target_scanner_ignores_dotted_files_and_handles_dev_tcp_endpoint():
    candidates = extract_target_candidates(
        "python3 server.py --output 01-nmap-full.txt "
        "bash -c 'sock.close(); s.close(); echo test > /dev/tcp/10.10.15.65/4445'"
    )

    assert "10.10.15.65" in candidates
    assert "10.10.15.65/44" not in candidates
    assert "server.py" not in candidates
    assert "01-nmap-full.txt" not in candidates
    assert "sock.close" not in candidates
    assert "s.close" not in candidates


def test_local_tmp_script_path_is_an_informational_reminder():
    result = command.check_local_artifact_paths("cat > /tmp/exploit.py <<'PY'\nprint('x')\nPY")
    assert result.infos == ["local script path uses /tmp; save it under $ENG_DIR/exploits instead"]


def test_on_session_reset_hook_none_session_id():
    """Verify _on_session_reset_hook handles None session_id without throwing or raising KeyError."""
    from plugins.violin_guard.hooks import _on_session_reset_hook

    _on_session_reset_hook(session_id=None, eng_dir=None)
