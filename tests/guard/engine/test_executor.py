import os
import sys
import time
from pathlib import Path

import pytest

from plugins.violin_guard.engine import execution


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
