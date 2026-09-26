import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from plugins.violin_guard.core.engagement import state
from plugins.violin_guard.engine import (
    execution,
    execution_lifecycle,
    execution_process,
    execution_support,
)


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
    assert receipt["receipt_kind"] == "execution"
    assert receipt["history_recorded"] is True


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


def test_status_capture_rewrite_surfaces_the_requested_command(tmp_path):
    """#87: the receipt explains the flag the guard injected, and keeps the command asked for."""
    eng = _engagement(tmp_path)
    receipt = execution.execute(
        "curl -sS http://10.10.10.10/api/orders",
        argv=[sys.executable, "-c", "print('probe')"],
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=10,
        label="proof-rewrite",
        ptt_task_id="PT-001",
    )

    assert " -i " in f" {receipt['command']} "
    assert " -i " not in f" {receipt['requested_command']} "
    assert receipt["command_note"] == "status capture injected for HTTP proof"
    manifest = eng / receipt["evidence_paths"]["manifest"]
    recorded = json.loads(manifest.read_text(encoding="utf-8"))
    assert recorded["requested_command"] == receipt["requested_command"]
    assert recorded["command"] == receipt["command"]


def test_unchanged_command_carries_no_rewrite_note(tmp_path):
    eng = _engagement(tmp_path)
    receipt = execution.execute(
        "echo violin-test",
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=10,
        label="no-rewrite",
    )

    assert "requested_command" not in receipt
    assert "command_note" not in receipt


def test_failed_to_start_is_audited_without_execution_credit(tmp_path, monkeypatch):
    eng = _engagement(tmp_path)
    reservation = state.reserve_sync_credit(eng, "recon", 2)
    before = state.sync_credit_remaining(eng, "recon")

    def fail_start(*_args, **_kwargs):
        raise OSError("launch denied")

    monkeypatch.setattr(subprocess, "Popen", fail_start)
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
    assert state.sync_credit_remaining(eng, "recon") == before
    assert not state.has_pending_sync(eng)
    state.release_reserved_sync_credit(eng, reservation)
    assert state.sync_credit_remaining(eng, "recon") == 10


def test_failed_to_track_terminates_and_accounts_conservatively(tmp_path, monkeypatch):
    eng = _engagement(tmp_path)
    monkeypatch.setattr(execution_process, "_process_create_time", lambda _proc: None)
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
    assert state.sync_credit_remaining(eng, "recon") == 9
    assert state.has_pending_sync(eng)


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


def test_background_target_execution_is_accounted_at_launch(tmp_path):
    eng = _engagement(tmp_path)
    receipt = execution.execute(
        "nmap 10.10.10.10",
        argv=[sys.executable, "-c", "import time; time.sleep(0.4)"],
        eng_dir=str(eng),
        phase="recon",
        ptt_task_id="PT-001",
        timeout_seconds=5,
        background=True,
    )

    assert receipt["status"] == "running"
    assert state.sync_credit_remaining(eng, "recon") == 9
    assert state.read_counts(eng)["commands"] == 1
    pending = state.get_pending_sync(eng)
    assert pending["commands"][0]["execution_id"] == receipt["execution_id"]


def test_identical_commands_are_separate_execution_history_entries(tmp_path):
    eng = _engagement(tmp_path)
    receipts = [
        execution.execute(
            "nmap 10.10.10.10",
            argv=[sys.executable, "-c", "print('same command')"],
            eng_dir=str(eng),
            phase="recon",
            ptt_task_id="PT-001",
            timeout_seconds=10,
        )
        for _ in range(2)
    ]

    assert receipts[0]["execution_id"] != receipts[1]["execution_id"]
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert history.count(" | execution_id=") == 2
    assert state.read_counts(eng)["commands"] == 2
    pending = state.get_pending_sync(eng)
    assert [item["execution_id"] for item in pending["commands"]] == [
        receipts[0]["execution_id"],
        receipts[1]["execution_id"],
    ]


def test_finalization_retry_reuses_terminal_intent_and_history_entry(tmp_path, monkeypatch):
    eng = _engagement(tmp_path)
    original_seal = execution_lifecycle.seal_execution_receipt
    failed = False

    def fail_first_seal(receipt, engagement):
        nonlocal failed
        if Path(engagement).resolve() == eng.resolve() and not failed:
            failed = True
            raise OSError("simulated crash before receipt publication")
        return original_seal(receipt, engagement)

    monkeypatch.setattr(execution_lifecycle, "seal_execution_receipt", fail_first_seal)
    with pytest.raises(OSError, match="simulated crash"):
        execution.execute(
            "echo recover-finalizer",
            eng_dir=str(eng),
            phase="recon",
            timeout_seconds=10,
        )

    manifest_path = next((eng / "evidence" / "executions").glob("*.json"))
    incomplete = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert incomplete["status"] == "finalizing"
    assert incomplete["terminal"]["status"] == "completed"
    assert (eng / "state" / "history.md").read_text(encoding="utf-8").count(" | execution_id=") == 1

    monkeypatch.setattr(execution_lifecycle, "seal_execution_receipt", original_seal)
    recovered = execution.status(str(eng), incomplete["execution_id"])
    assert recovered["status"] == "completed"
    assert recovered["history_recorded"] is True
    assert "terminal" not in recovered
    assert (eng / "state" / "history.md").read_text(encoding="utf-8").count(" | execution_id=") == 1


def test_stale_launch_intent_is_charged_and_finalized_as_unknown(tmp_path):
    eng = _engagement(tmp_path)
    execution_id = "12345678-1234-4234-8234-123456789abc"
    manifest = eng / "evidence" / "executions" / "20260923-12345678-command.json"
    record = {
        "schema_version": execution.SCHEMA_VERSION,
        "execution_id": execution_id,
        "status": "starting",
        "command": "nmap 10.10.10.10",
        "phase": "recon",
        "ptt_task_id": "PT-001",
        "started_at": "2026-09-23T11:00:00Z",
        "intent_at": "2026-09-23T11:00:00Z",
        "background": False,
        "evidence_paths": {
            "manifest": manifest.relative_to(eng).as_posix(),
            "stdout": None,
            "stderr": None,
        },
        "declared_evidence_outputs": [],
    }
    state.atomic_json(manifest, record)

    recovered = execution.status(str(eng), execution_id)

    assert recovered["status"] == "lost"
    assert state.sync_credit_remaining(eng, "recon") == 9
    assert state.read_counts(eng)["commands"] == 1
    assert state.get_pending_sync(eng)["commands"][0]["execution_id"] == execution_id


def test_launch_accounting_retry_does_not_double_charge_or_tick(tmp_path, monkeypatch):
    eng = _engagement(tmp_path)
    original_mutate = state.mutate_json
    failed_counts_write = False

    def fail_first_counts_write(path, mutation):
        nonlocal failed_counts_write
        if path.name == "counts.json" and not failed_counts_write:
            failed_counts_write = True
            raise OSError("simulated crash after sync accounting")
        return original_mutate(path, mutation)

    monkeypatch.setattr(state, "mutate_json", fail_first_counts_write)
    with pytest.raises(OSError, match="after sync accounting"):
        state.commit_execution_start(eng, "nmap 10.0.0.1", "recon", "PT-001", "execution-1")
    first_retry = state.commit_execution_start(
        eng, "nmap 10.0.0.1", "recon", "PT-001", "execution-1"
    )
    second_retry = state.commit_execution_start(
        eng, "nmap 10.0.0.1", "recon", "PT-001", "execution-1"
    )

    assert first_retry[:3] == second_retry[:3]
    assert first_retry[0] == 9
    assert first_retry[3] is True
    assert second_retry[3] is False
    assert state.read_counts(eng)["commands"] == 1
    pending = state.get_pending_sync(eng)
    assert [item["execution_id"] for item in pending["commands"]] == ["execution-1"]


def test_reserved_launch_accounting_is_idempotent(tmp_path):
    eng = _engagement(tmp_path)
    reservation = state.reserve_sync_credit(eng, "recon", 2)

    first = state.commit_execution_start(
        eng, "nmap 10.0.0.1", "recon", "PT-001", "execution-1", reservation
    )
    retry = state.commit_execution_start(
        eng, "nmap 10.0.0.1", "recon", "PT-001", "execution-1", reservation
    )

    assert first[:3] == retry[:3]
    assert first[3] is True
    assert retry[3] is False
    assert first[0] == 8
    assert first[1] is True
    assert state.read_counts(eng)["commands"] == 1
    assert (
        state.read_json(eng / "state" / "sync.json")["reservations"][reservation]["remaining"] == 1
    )


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
    proc = psutil.Process(os.getpid())
    record = {"pid": proc.pid, "pid_create_time": proc.create_time()}
    assert execution_support._matching_process(record) is not None
    record["pid_create_time"] += 10
    assert execution_support._matching_process(record) is None


def test_executor_rejects_cwd_escape(tmp_path):
    eng = _engagement(tmp_path)
    with pytest.raises(ValueError, match="inside the engagement"):
        execution.execute("echo blocked", eng_dir=str(eng), phase="recon", cwd="..")


def _write_file_argv(path: Path, content: str) -> list[str]:
    return [
        sys.executable,
        "-c",
        "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2], encoding='utf-8')",
        str(path),
        content,
    ]


def _manifest_record(eng: Path, receipt: dict) -> dict:
    return json.loads((eng / receipt["evidence_paths"]["manifest"]).read_text(encoding="utf-8"))
