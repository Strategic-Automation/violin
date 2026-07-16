import sys
import time
from pathlib import Path

import pytest

from plugins.violin_guard.core import adapters, execution


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


def test_executor_rejects_cwd_escape(tmp_path):
    eng = _engagement(tmp_path)
    with pytest.raises(ValueError, match="inside the engagement"):
        execution.execute("echo blocked", eng_dir=str(eng), phase="recon", cwd="..")


def test_adapter_builders_are_structured_and_bounded():
    assert (
        adapters.build_nmap({"target": "10.0.0.1", "ports": "80,443"})
        == "nmap -sCV -p 80,443 10.0.0.1"
    )
    with pytest.raises(adapters.AdapterError, match="1-65535"):
        adapters.build_nmap({"target": "10.0.0.1", "ports": "-p-"})
    assert "FUZZ" in adapters.build_ffuf(
        {
            "url": "http://10.0.0.1/FUZZ",
            "wordlist": "/tmp/common.txt",
        }
    )
    with pytest.raises(adapters.AdapterError):
        adapters.build_nmap({"target": "10.0.0.1", "ports": "80; rm -rf /"})


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
