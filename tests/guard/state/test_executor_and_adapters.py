import json
import os
import sys
import time
from pathlib import Path

import pytest

from plugins.violin_guard import adapters, execution
from plugins.violin_guard.handlers import adapter_handlers


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    (eng / "state").mkdir(parents=True)
    (eng / "evidence").mkdir()
    (eng / "state" / "history.md").write_text("# History\n", encoding="utf-8")
    return eng


def test_local_executor_records_receipt_and_history(tmp_path):
    eng = _engagement(tmp_path)
    receipt = execution.execute(
        "echo violin-test",
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=10,
        label="smoke",
    )
    assert receipt["executed"] is True
    assert receipt["exit_code"] == 0
    assert "violin-test" in receipt["stdout_preview"]
    assert (eng / receipt["evidence_paths"]["manifest"]).exists()
    assert "echo violin-test" in (eng / "state" / "history.md").read_text(encoding="utf-8")


def test_structured_argv_preserves_argument_boundaries(tmp_path):
    eng = _engagement(tmp_path)
    value = "value with spaces (and parentheses)"
    receipt = execution.execute(
        "echo structured-argv",
        argv=[sys.executable, "-c", "import sys; print(sys.argv[1])", value],
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=10,
    )

    assert receipt["exit_code"] == 0
    assert receipt["stdout_preview"].strip() == value


def test_failed_to_start_is_audited_without_execution_credit(tmp_path, monkeypatch):
    eng = _engagement(tmp_path)
    reservation = execution.state.reserve_sync_credit(eng, "recon", 2)
    before = execution.state.sync_credit_remaining(eng, "recon")

    def fail_start(*_args, **_kwargs):
        raise OSError("launch denied")

    monkeypatch.setattr(execution.subprocess, "Popen", fail_start)
    receipt = execution.execute(
        "nmap 10.10.10.10",
        argv=[sys.executable, "-c", "print('never')"],
        eng_dir=str(eng),
        phase="recon",
        backend="local",
        ptt_task_id="PT-001",
        sync_reservation=reservation,
    )
    assert receipt["status"] == "failed_to_start"
    assert receipt["executed"] is False
    assert execution.state.sync_credit_remaining(eng, "recon") == before
    assert not execution.state.has_pending_sync(eng)
    execution.state.release_reserved_sync_credit(eng, reservation)
    assert execution.state.sync_credit_remaining(eng, "recon") == 10


def test_failed_to_track_terminates_and_accounts_conservatively(tmp_path, monkeypatch):
    eng = _engagement(tmp_path)
    monkeypatch.setattr(execution, "_process_create_time", lambda _proc: None)
    receipt = execution.execute(
        "tracked command",
        argv=[sys.executable, "-c", "import time; time.sleep(10)"],
        eng_dir=str(eng),
        phase="recon",
        backend="local",
        ptt_task_id="PT-001",
    )
    assert receipt["status"] == "failed_to_track"
    assert receipt["executed"] is True
    assert execution.state.sync_credit_remaining(eng, "recon") == 9
    assert execution.state.has_pending_sync(eng)


def test_background_execution_is_tracked_until_completion(tmp_path):
    eng = _engagement(tmp_path)
    receipt = execution.execute(
        "echo managed-listener",
        argv=[sys.executable, "-c", "import time; print('ready'); time.sleep(0.2)"],
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=5,
        background=True,
    )

    assert receipt["status"] == "running"
    assert isinstance(receipt["pid"], int)
    assert isinstance(receipt["pid_create_time"], float)
    assert receipt["deadline_at"].endswith("Z")
    deadline = time.monotonic() + 5
    current = receipt
    while current["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
        current = execution.status(str(eng), receipt["execution_id"])

    assert current["status"] == "completed"
    assert current["history_recorded"] is True
    assert "echo managed-listener" in (eng / "state" / "history.md").read_text(encoding="utf-8")


def test_background_execution_can_be_cancelled_by_execution_id(tmp_path):
    eng = _engagement(tmp_path)
    receipt = execution.execute(
        "echo cancellable-listener",
        argv=[sys.executable, "-c", "import time; time.sleep(30)"],
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=60,
        background=True,
    )

    cancelled = execution.cancel(str(eng), receipt["execution_id"])
    assert cancelled["cancel_requested"] is True
    deadline = time.monotonic() + 5
    current = cancelled
    while current["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
        current = execution.status(str(eng), receipt["execution_id"])
    assert current["status"] == "cancelled"


def test_process_identity_rejects_reused_pid():
    proc = execution.psutil.Process(os.getpid())
    record = {"pid": proc.pid, "pid_create_time": proc.create_time()}
    assert execution._matching_process(record) is not None
    record["pid_create_time"] += 10
    assert execution._matching_process(record) is None


def test_executor_rejects_cwd_escape(tmp_path):
    eng = _engagement(tmp_path)
    with pytest.raises(ValueError, match="inside the engagement"):
        execution.execute("echo blocked", eng_dir=str(eng), phase="recon", cwd="..")


def test_adapter_builders_are_structured_and_bounded():
    assert "FUZZ" in adapters.build_ffuf(
        {
            "url": "http://10.0.0.1/FUZZ",
            "wordlist": "/tmp/common.txt",
        }
    )


def test_ffuf_wordlist_resolution_uses_requested_then_portable_fallbacks(tmp_path, monkeypatch):
    requested = tmp_path / "requested.txt"
    requested.write_text("admin\n", encoding="utf-8")
    assert adapters.resolve_ffuf_wordlist(requested) == str(requested)

    seclists = tmp_path / "SecLists"
    fallback = seclists / "Discovery" / "Web-Content" / "common.txt"
    fallback.parent.mkdir(parents=True)
    fallback.write_text("api\n", encoding="utf-8")
    monkeypatch.setenv("SECLISTS", str(seclists))
    assert adapters.resolve_ffuf_wordlist(tmp_path / "missing.txt") == str(fallback)


def test_ffuf_wordlist_resolution_has_actionable_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("SECLISTS", raising=False)
    monkeypatch.setattr(adapters.Path, "is_file", lambda _path: False)
    with pytest.raises(adapters.AdapterError, match="install the seclists package"):
        adapters.resolve_ffuf_wordlist(tmp_path / "missing.txt")


def test_ffuf_handler_dispatches_the_resolved_wordlist(monkeypatch):
    captured = {}

    def fake_exec(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return json.dumps({"status": "ok"})

    monkeypatch.setattr(
        adapter_handlers, "resolve_ffuf_wordlist", lambda _requested: "/resolved/common.txt"
    )
    monkeypatch.setattr(adapter_handlers, "_get_handle_exec", lambda: fake_exec)
    result = json.loads(
        adapter_handlers.handle_ffuf(
            {
                "eng_dir": "/eng",
                "phase": "RECON",
                "target": "https://target.example",
                "url": "https://target.example/FUZZ",
                "wordlist": "/missing/common.txt",
            }
        )
    )
    assert result["status"] == "ok"
    assert captured["args"]["wordlist"] == "/resolved/common.txt"
    assert "-w /resolved/common.txt" in captured["args"]["command"]
    assert "/resolved/common.txt" in captured["kwargs"]["_internal_argv"]


def test_ffuf_handler_resolves_auth_token_from_engagement_evidence(tmp_path, monkeypatch):
    engagement = tmp_path / "eng"
    token_path = engagement / "evidence" / "recon" / "access.token"
    token_path.parent.mkdir(parents=True)
    token_path.write_text("secret-token\n", encoding="utf-8")
    captured = {}

    def fake_exec(args, **kwargs):
        captured["args"] = args
        return json.dumps({"status": "ok"})

    monkeypatch.setattr(
        adapter_handlers, "resolve_ffuf_wordlist", lambda _requested: "/resolved/common.txt"
    )
    monkeypatch.setattr(adapter_handlers, "_get_handle_exec", lambda: fake_exec)
    result = json.loads(
        adapter_handlers.handle_ffuf(
            {
                "eng_dir": str(engagement),
                "phase": "RECON",
                "target": "https://target.example",
                "url": "https://target.example/FUZZ",
                "auth_token_file": "evidence/recon/access.token",
            }
        )
    )
    assert result["status"] == "ok"
    assert "Authorization: Bearer secret-token" in captured["args"]["headers"]


def test_ffuf_auth_token_file_must_be_under_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(
        adapter_handlers, "resolve_ffuf_wordlist", lambda _requested: "/resolved/common.txt"
    )
    result = json.loads(
        adapter_handlers.handle_ffuf(
            {
                "eng_dir": str(tmp_path / "eng"),
                "phase": "RECON",
                "target": "https://target.example",
                "url": "https://target.example/FUZZ",
                "auth_token_file": "state/access.token",
            }
        )
    )
    assert result["status"] == "error"
    assert "inside the engagement evidence directory" in result["error"]


def test_listener_flags_are_pinned_per_netcat_variant():
    assert adapters.detect_netcat_variant("OpenBSD netcat (Debian patchlevel 1.219-1)") == "openbsd"
    assert adapters.detect_netcat_variant("Ncat: Version 7.95 ( https://nmap.org/ncat )") == "ncat"
    assert adapters.detect_netcat_variant("[v1.10-47] traditional netcat") == "traditional"

    openbsd = adapters.build_netcat_listener(
        {"binary": "nc", "variant": "openbsd", "port": 4444, "keep_open": True}
    )
    assert openbsd == "nc -l -v -k 4444"
    ncat = adapters.build_netcat_listener(
        {"binary": "ncat", "variant": "ncat", "port": 4444, "keep_open": True}
    )
    assert ncat == "ncat --listen --verbose --keep-open 4444"
    with pytest.raises(adapters.AdapterError, match="no supported keep-open"):
        adapters.build_netcat_listener(
            {"binary": "nc", "variant": "traditional", "port": 4444, "keep_open": True}
        )


def test_listener_variant_detection_is_cached(monkeypatch):
    calls = []
    adapters._installed_netcat_variant.cache_clear()
    monkeypatch.setattr(adapters.shutil, "which", lambda _: "/usr/bin/nc")

    def fake_run(*args, **kwargs):
        calls.append(args)
        return adapters.subprocess.CompletedProcess(args[0], 0, "", "OpenBSD netcat")

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)
    first = adapters.build_netcat_listener({"binary": "nc", "port": 4444})
    second = adapters.build_netcat_listener({"binary": "nc", "port": 5555})

    assert first.endswith("4444")
    assert second.endswith("5555")
    assert len(calls) == 1
    adapters._installed_netcat_variant.cache_clear()


def test_search_exploit_reports_missing_tool(monkeypatch):
    monkeypatch.setattr(adapters.shutil, "which", lambda _: None)
    result = adapters.search_exploit({"product": "OpenSSH", "version": "9.0"})
    assert result["available"] is False
    assert result["executed_candidates"] is not True


def test_projectdiscovery_httpx_detection():
    assert adapters.is_projectdiscovery_httpx("httpx v1.3.0 ProjectDiscovery") is True
    assert adapters.is_projectdiscovery_httpx("-status-code -tech-detect") is True
    assert adapters.is_projectdiscovery_httpx("Error: Option '-h' requires 2 arguments.") is False
    assert adapters.is_projectdiscovery_httpx("httpx [OPTIONS] URL") is False


def test_httpx_binary_resolution_detects_python_httpx(monkeypatch):
    adapters._installed_httpx_binary.cache_clear()
    monkeypatch.setattr(
        adapters.shutil,
        "which",
        lambda name: "/usr/bin/httpx" if name == "httpx" else None,
    )

    def fake_run(cmd, *args, **kwargs):
        return adapters.subprocess.CompletedProcess(
            cmd, 1, "", "Error: Option '-h' requires 2 arguments."
        )

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    with pytest.raises(adapters.AdapterError, match="Python httpx HTTP client"):
        adapters.build_httpx({"target": "http://10.0.0.1"})

    probe = adapters.available("httpx")
    assert probe.available is False
    assert "Python httpx" in probe.message

    adapters._installed_httpx_binary.cache_clear()


def test_httpx_binary_resolution_prefers_httpx_toolkit(monkeypatch):
    adapters._installed_httpx_binary.cache_clear()
    monkeypatch.setattr(
        adapters.shutil,
        "which",
        lambda name: "/usr/bin/httpx-toolkit" if name == "httpx-toolkit" else "/usr/bin/httpx",
    )
    cmd = adapters.build_httpx({"target": "http://10.0.0.1"})
    assert cmd.startswith("httpx-toolkit")
    adapters._installed_httpx_binary.cache_clear()


def test_httpx_binary_resolution_returns_false_when_missing(monkeypatch):
    adapters._installed_httpx_binary.cache_clear()
    monkeypatch.setattr(adapters.shutil, "which", lambda name: None)
    probe = adapters.available("httpx")
    assert probe.available is False
    assert "not installed" in probe.message

    with pytest.raises(adapters.AdapterError, match="not installed or not on PATH"):
        adapters.build_httpx({"target": "http://10.0.0.1"})
    adapters._installed_httpx_binary.cache_clear()
