"""Accounting failures cannot erase the fact that a command launched."""

import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from plugins.violin_guard.core.engagement import state
from plugins.violin_guard.core.evidence import receipt_integrity
from plugins.violin_guard.core.results import GuardResult
from plugins.violin_guard.engine import execution, execution_lifecycle
from plugins.violin_guard.handlers import exec_handlers, ptt_review


def test_double_accounting_failure_finalizes_and_recovers_truthfully(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    (tmp_path / "state/history.md").write_text("# History\n", encoding="utf-8")
    (tmp_path / "state/ptt.md").write_text(
        "## Phase: RECON\n\n| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [~] | Probe | active |\n",
        encoding="utf-8",
    )
    calls = []
    original = state.commit_execution_start

    def fail_accounting(*args, **kwargs):
        calls.append(args)
        raise OSError("accounting write unavailable")

    monkeypatch.setattr(state, "commit_execution_start", fail_accounting)
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: GuardResult())
    response = json.loads(
        exec_handlers.handle_exec(
            {"eng_dir": str(tmp_path), "phase": "recon", "command": "guarded probe"},
            _internal_argv=[sys.executable, "-c", "import time; time.sleep(5)"],
        )
    )
    assert len(calls) == 2
    assert response["status"] == "execution_failed"
    assert response["executed"] is True
    assert response["execution_status"] == "failed_to_track"
    assert response["accounting_pending"] is True
    assert response["sync_required"] is True
    assert response["history_recorded"] is True
    manifest = tmp_path / response["evidence_paths"]["manifest"]
    assert json.loads(manifest.read_text(encoding="utf-8"))["status"] == "failed_to_track"
    assert execution.status(str(tmp_path), response["execution_id"])["accounting_pending"]

    monkeypatch.setattr(state, "commit_execution_start", original)
    recovered = execution.status(str(tmp_path), response["execution_id"])
    assert recovered["accounting_pending"] is False
    assert "accounting_error" not in recovered
    assert state.read_counts(tmp_path)["commands"] == 1

    execution.status(str(tmp_path), response["execution_id"])
    assert state.read_counts(tmp_path)["commands"] == 1


def test_history_failure_reports_execution_and_preserves_terminal_intent(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    (tmp_path / "state/ptt.md").write_text(
        "## Phase: RECON\n\n| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [~] | Probe | active |\n",
        encoding="utf-8",
    )
    original = execution_lifecycle.append_history

    def fail_history(*args, **kwargs):
        raise OSError("history write unavailable")

    monkeypatch.setattr(execution_lifecycle, "append_history", fail_history)
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: GuardResult())
    response = json.loads(
        exec_handlers.handle_exec(
            {"eng_dir": str(tmp_path), "phase": "recon", "command": "guarded probe"},
            _internal_argv=[sys.executable, "-c", "print('done')"],
        )
    )
    assert response["status"] == "execution_failed"
    assert response["executed"] is True
    assert response["execution_status"] == "failed_to_finalize"
    manifest = tmp_path / response["evidence_paths"]["manifest"]
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert stored["status"] == "finalizing"
    assert stored["terminal"]["status"] == "completed"
    assert stored["terminal"]["exit_code"] == 0
    monkeypatch.setattr(execution_lifecycle, "append_history", original)
    recovered = execution.status(str(tmp_path), response["execution_id"])
    assert recovered["status"] == "completed"
    assert recovered["history_recorded"] is True
    execution.status(str(tmp_path), response["execution_id"])
    assert state.read_counts(tmp_path)["commands"] == 1


@pytest.fixture
def pending_receipt(tmp_path, monkeypatch, request):
    (tmp_path / "state").mkdir()
    evidence = tmp_path / "evidence/executions"
    evidence.mkdir(parents=True)
    output = evidence / "stdout.txt"
    output.write_text("original proof", encoding="utf-8")
    monkeypatch.setattr(
        receipt_integrity, "_RUNTIME_KEY", b"h" * 32 if request.param == "hmac" else None
    )
    monkeypatch.setattr(
        receipt_integrity, "_RUNTIME_SIGNING_KEY", b"e" * 32 if request.param == "ed25519" else None
    )
    execution_id = str(uuid.uuid4())
    manifest = evidence / f"{execution_id}.json"
    record = receipt_integrity.seal_execution_receipt(
        {
            "execution_id": execution_id,
            "command": "guarded probe",
            "phase": "recon",
            "ptt_task_id": "PT-001",
            "status": "failed_to_track",
            "history_recorded": True,
            "receipt_kind": "execution",
            "accounting_pending": True,
            "accounting_error": "write unavailable",
            "evidence_paths": {
                "stdout": output.relative_to(tmp_path).as_posix(),
                "manifest": manifest.relative_to(tmp_path).as_posix(),
            },
        },
        tmp_path,
    )
    state.atomic_json(manifest, record)
    return tmp_path, execution_id, manifest, output, record


@pytest.mark.parametrize("pending_receipt", ["hmac", "ed25519"], indirect=True)
@pytest.mark.parametrize("evidence_change", ["changed", "removed"])
def test_accounting_recovery_preserves_stale_evidence(pending_receipt, evidence_change):
    engagement, execution_id, manifest, output, original = pending_receipt
    if evidence_change == "changed":
        output.write_text("changed proof", encoding="utf-8")
    else:
        output.unlink()
    with ThreadPoolExecutor(max_workers=4) as pool:
        recovered = list(
            pool.map(lambda _: execution.status(str(engagement), execution_id), range(4))
        )
    assert all(item["accounting_pending"] is False for item in recovered)
    stored = state.read_json(manifest)
    assert stored[receipt_integrity.DIGESTS_FIELD] == original[receipt_integrity.DIGESTS_FIELD]
    assert receipt_integrity.verify_runtime_receipt(stored, engagement).stale == (
        output.relative_to(engagement).as_posix(),
    )
    assert state.read_counts(engagement)["commands"] == 1
    assert len(state.get_pending_sync(engagement)["commands"]) == 1


@pytest.mark.parametrize("pending_receipt", ["hmac", "ed25519"], indirect=True)
@pytest.mark.parametrize("tamper", ["command", "digests", "unsigned", "foreign", "terminal"])
def test_accounting_recovery_rejects_untrusted_receipt_before_mutation(pending_receipt, tamper):
    engagement, execution_id, manifest, _, record = pending_receipt
    if tamper == "command":
        record["command"] = "another command"
    elif tamper == "digests":
        record[receipt_integrity.DIGESTS_FIELD] = {}
    elif tamper == "unsigned":
        record.pop(receipt_integrity.SIGNATURE_FIELD, None)
        record.pop(receipt_integrity.PUBLIC_SIGNATURE_FIELD, None)
    elif tamper == "terminal":
        record.update(
            status="finalizing",
            history_recorded=False,
            terminal={"status": "completed", "exit_code": 0},
        )
    else:
        record = receipt_integrity.seal_execution_receipt(
            record, engagement, key=b"f" * 32, signing_key=b"f" * 32
        )
    state.atomic_json(manifest, record)
    before = manifest.read_bytes()
    result = execution.status(str(engagement), execution_id)
    assert result["accounting_pending"] is True
    assert "unsigned or foreign" in result["accounting_error"]
    assert state.read_counts(engagement)["commands"] == 0
    assert state.get_pending_sync(engagement) is None
    assert manifest.read_bytes() == before


@pytest.mark.parametrize("continue_on_error", [False, True])
@pytest.mark.parametrize("failure_index", [0, 1])
def test_burst_retains_launched_credit_until_accounting_recovers(
    tmp_path, monkeypatch, continue_on_error, failure_index
):
    (tmp_path / "state").mkdir()
    (tmp_path / "state/ptt.md").write_text(
        "## Phase: RECON\n\n| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [~] | Probe | active |\n",
        encoding="utf-8",
    )
    original = state.commit_execution_start

    commands = ["probe one", "probe two", "probe three"]

    def fail_accounting(*args, **kwargs):
        if args[1] == commands[failure_index]:
            raise OSError("accounting write unavailable")
        return original(*args, **kwargs)

    monkeypatch.setattr(state, "commit_execution_start", fail_accounting)
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: GuardResult())
    execute = execution.execute

    def run_local(**kwargs):
        return execute(**kwargs, argv=[sys.executable, "-c", "print('probe')"])

    monkeypatch.setattr(execution, "execute", run_local)
    result = json.loads(
        exec_handlers.handle_exec_burst(
            {
                "eng_dir": str(tmp_path),
                "phase": "recon",
                "commands": commands,
                "continue_on_error": continue_on_error,
            }
        )
    )
    assert result["status"] == "batch_stopped"
    assert result["executed"] == failure_index + 1
    assert result["review_required"] is True
    assert result["skipped"] == len(commands) - failure_index - 1
    runtime = state._read_runtime(tmp_path)
    assert len(runtime.sync.reservations) == 1
    assert next(iter(runtime.sync.reservations.values())).remaining == 1
    assert runtime.sync.credit == state.sync_credit_limit("recon") - failure_index - 1
    before = (tmp_path / "state/runtime.json").read_bytes()
    with pytest.raises(ValueError, match="reservation"):
        state.clear_pending_sync(tmp_path)
    with pytest.raises(ValueError, match="reservation"):
        state.reserve_sync_credit(tmp_path, "recon", 1)
    review = json.loads(ptt_review.handle_review_batch({"eng_dir": str(tmp_path)}))
    assert review["released"] is False
    assert (tmp_path / "state/runtime.json").read_bytes() == before
    monkeypatch.setattr(state, "commit_execution_start", original)
    execution_id = result["results"][failure_index]["execution_id"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        recovered = list(
            pool.map(lambda _: execution.status(str(tmp_path), execution_id), range(4))
        )
    assert all(not item.get("accounting_pending") for item in recovered)
    assert not state._read_runtime(tmp_path).sync.reservations
    assert state.read_counts(tmp_path)["commands"] == failure_index + 1
    assert len(state.get_pending_sync(tmp_path)["commands"]) == failure_index + 1
    state.clear_pending_sync(tmp_path)
    assert state.sync_credit_remaining(tmp_path, "recon") == state.sync_credit_limit("recon")


@pytest.mark.parametrize("pending_receipt", ["hmac", "ed25519"], indirect=True)
def test_accounting_retry_after_receipt_write_failure_is_idempotent(pending_receipt, monkeypatch):
    engagement, execution_id, manifest, _, original = pending_receipt
    atomic_json = state.atomic_json

    def fail_receipt_write(path, record):
        if path == manifest:
            raise OSError("receipt write unavailable")
        return atomic_json(path, record)

    monkeypatch.setattr(state, "atomic_json", fail_receipt_write)
    result = execution.status(str(engagement), execution_id)
    assert result["accounting_pending"] is True
    assert "receipt write unavailable" in result["accounting_error"]
    assert state.read_counts(engagement)["commands"] == 1
    assert state.read_json(manifest) == original
    monkeypatch.setattr(state, "atomic_json", atomic_json)
    result = execution.status(str(engagement), execution_id)
    assert result["accounting_pending"] is False
    assert state.read_counts(engagement)["commands"] == 1
    assert len(state.get_pending_sync(engagement)["commands"]) == 1
    assert receipt_integrity.verify_runtime_receipt(result, engagement).stale == ()


def test_burst_refunds_commands_when_process_never_starts(tmp_path, monkeypatch):
    from plugins.violin_guard.engine import execution_process

    (tmp_path / "state").mkdir()
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: GuardResult())

    def fail_process_start(*args, **kwargs):
        raise OSError("process unavailable")

    monkeypatch.setattr(execution_process.subprocess, "Popen", fail_process_start)
    execute = execution.execute
    monkeypatch.setattr(
        execution,
        "execute",
        lambda **kwargs: execute(**kwargs, argv=[sys.executable, "-c", "print('probe')"]),
    )
    result = json.loads(
        exec_handlers.handle_exec_burst(
            {
                "eng_dir": str(tmp_path),
                "phase": "recon",
                "backend": "local",
                "commands": ["probe one", "probe two"],
            }
        )
    )
    assert result["executed"] == 0
    assert result["review_required"] is False
    assert not state._read_runtime(tmp_path).sync.reservations
    assert state.sync_credit_remaining(tmp_path, "recon") == state.sync_credit_limit("recon")
    assert state.read_counts(tmp_path)["commands"] == 0


@pytest.mark.parametrize("signer", ["hmac", "ed25519"])
def test_unfinished_receipt_is_finalized_before_signed_accounting_recovery(
    tmp_path, monkeypatch, signer
):
    (tmp_path / "state").mkdir()
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"h" * 32 if signer == "hmac" else None)
    monkeypatch.setattr(
        receipt_integrity, "_RUNTIME_SIGNING_KEY", b"e" * 32 if signer == "ed25519" else None
    )
    original_account = state.commit_execution_start
    original_history = execution_lifecycle.append_history

    def fail_write(*args, **kwargs):
        raise OSError("write unavailable")

    monkeypatch.setattr(state, "commit_execution_start", fail_write)
    monkeypatch.setattr(execution_lifecycle, "append_history", fail_write)
    result = execution.execute(
        "guarded probe",
        eng_dir=str(tmp_path),
        phase="recon",
        backend="local",
        ptt_task_id="PT-001",
        argv=[sys.executable, "-c", "print('probe')"],
    )
    assert result["executed"] is True
    assert result["accounting_pending"] is True
    assert result["status"] == "failed_to_finalize"
    monkeypatch.setattr(state, "commit_execution_start", original_account)
    monkeypatch.setattr(execution_lifecycle, "append_history", original_history)
    recovered = execution.status(str(tmp_path), result["execution_id"])
    assert recovered["history_recorded"] is True
    assert recovered["accounting_pending"] is False
    assert receipt_integrity.verify_runtime_receipt(recovered, tmp_path).stale == ()
    assert state.read_counts(tmp_path)["commands"] == 1
