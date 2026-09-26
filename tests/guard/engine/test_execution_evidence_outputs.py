"""Receipt identity for evidence outputs, including concurrent executions."""

import json
import os
import sys
import time
from pathlib import Path

import pytest

from plugins.violin_guard.core.evidence import findings, receipt_integrity
from plugins.violin_guard.engine import execution, execution_support


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    (eng / "state").mkdir(parents=True)
    (eng / "evidence").mkdir()
    (eng / "state" / "history.md").write_text("# History\n", encoding="utf-8")
    return eng


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


def test_receipt_seals_only_the_outputs_its_command_wrote(tmp_path):
    """#203: a receipt's evidence identity is what its own command wrote."""
    eng = _engagement(tmp_path)
    written = eng / "evidence" / "recon" / "written.txt"
    untouched = eng / "evidence" / "recon" / "untouched.txt"
    untouched.parent.mkdir(parents=True)
    untouched.write_text("from a batch-mate\n", encoding="utf-8")

    receipt = execution.execute(
        "python -c 'write one declared output'",
        argv=_write_file_argv(written, "written\n"),
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=["evidence/recon/written.txt", "evidence/recon/untouched.txt"],
    )

    assert receipt["exit_code"] == 0
    assert _manifest_record(eng, receipt)["declared_evidence_outputs"] == [
        "evidence/recon/written.txt"
    ]


def test_a_batch_mate_rewrite_does_not_invalidate_another_command(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    """#203: two commands declaring one batch-wide union must not share evidence identity."""
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", b"r" * 32)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    eng = _engagement(tmp_path)
    first_output = eng / "evidence" / "recon" / "first.txt"
    second_output = eng / "evidence" / "recon" / "second.txt"
    first_output.parent.mkdir(parents=True)
    union = ["evidence/recon/first.txt", "evidence/recon/second.txt"]

    first = execution.execute(
        "python -c 'write the first output'",
        argv=_write_file_argv(first_output, "first\n"),
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=union,
    )
    second = execution.execute(
        "python -c 'write the second output'",
        argv=_write_file_argv(second_output, "second\n"),
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=union,
    )
    assert _manifest_record(eng, first)["declared_evidence_outputs"] == ["evidence/recon/first.txt"]
    assert _manifest_record(eng, second)["declared_evidence_outputs"] == [
        "evidence/recon/second.txt"
    ]

    # A later batch step rewrites its own output. The earlier receipt must still
    # authenticate the file its own command produced.
    second_output.write_text("rewritten by a later probe\n", encoding="utf-8")
    findings.submit_finding(
        eng,
        title="Rests on the first command's own output",
        severity="High",
        summary="Reproduced with receipt-authenticated evidence.",
        receipt_paths=[first["evidence_paths"]["manifest"]],
        evidence_paths=["evidence/recon/first.txt"],
    )


def test_a_rewrite_with_unchanged_size_and_mtime_is_still_sealed(tmp_path):
    """#203: provenance is content, not stat.

    A probe that rewrites its output byte-for-byte without changing the length or
    the timestamp (`cp -p`, `rsync -t`, `os.utime` after write, a coarse-timestamp
    filesystem) must still be recorded as produced. Stat alone silently discards
    genuine proof and every finding citing it is then rejected.
    """
    eng = _engagement(tmp_path)
    probe = eng / "evidence" / "recon" / "probe.txt"
    probe.parent.mkdir(parents=True)
    probe.write_text("stale\n", encoding="utf-8")
    unchanged_stat = probe.stat()
    assert len("stale\n") == len("proof\n")

    receipt = execution.execute(
        "python -c 'rewrite the output in place'",
        argv=[
            sys.executable,
            "-c",
            "import os, pathlib, sys; p = pathlib.Path(sys.argv[1]); "
            "p.write_text(sys.argv[2], encoding='utf-8'); "
            "os.utime(p, ns=(int(sys.argv[3]), int(sys.argv[3])))",
            str(probe),
            "proof\n",
            str(unchanged_stat.st_mtime_ns),
        ],
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=["evidence/recon/probe.txt"],
    )

    assert probe.stat().st_size == unchanged_stat.st_size
    assert probe.stat().st_mtime_ns == unchanged_stat.st_mtime_ns
    assert _manifest_record(eng, receipt)["declared_evidence_outputs"] == [
        "evidence/recon/probe.txt"
    ]


def test_a_background_command_still_seals_only_its_own_output(tmp_path):
    """#203: background and status()/cancel() finalizers narrow identically."""
    eng = _engagement(tmp_path)
    written = eng / "evidence" / "recon" / "written.txt"
    untouched = eng / "evidence" / "recon" / "untouched.txt"
    untouched.parent.mkdir(parents=True)
    untouched.write_text("from a batch-mate\n", encoding="utf-8")

    receipt = execution.execute(
        "python -c 'write one declared output'",
        argv=_write_file_argv(written, "written\n"),
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=["evidence/recon/written.txt", "evidence/recon/untouched.txt"],
        background=True,
    )
    deadline = time.monotonic() + 15
    current = receipt
    while current.get("status") == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
        current = execution.status(str(eng), receipt["execution_id"])

    assert current["status"] == "completed"
    assert _manifest_record(eng, receipt)["declared_evidence_outputs"] == [
        "evidence/recon/written.txt"
    ]


def test_concurrent_commands_cannot_claim_the_same_evidence_output(tmp_path):
    eng = _engagement(tmp_path)
    output = eng / "evidence" / "recon" / "shared.txt"
    release = eng / "state" / "release-first-command"
    output.parent.mkdir(parents=True)
    argv = [
        sys.executable,
        "-c",
        "import pathlib, sys, time\n"
        "output = pathlib.Path(sys.argv[1])\n"
        "release = pathlib.Path(sys.argv[2])\n"
        "deadline = time.monotonic() + 10\n"
        "while not release.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.01)\n"
        "output.write_text('written by first command\\n', encoding='utf-8')",
        str(output),
        str(release),
    ]
    first = execution.execute(
        "wait, then write the declared evidence output",
        argv=argv,
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=20,
        ptt_task_id="PT-001",
        evidence_outputs=["evidence/recon/shared.txt"],
        background=True,
    )

    with pytest.raises(ValueError, match="already in use"):
        execution.execute(
            "write the same declared evidence output",
            argv=_write_file_argv(output, "written by second command\\n"),
            eng_dir=str(eng),
            phase="recon",
            timeout_seconds=20,
            ptt_task_id="PT-001",
            evidence_outputs=["evidence/recon/shared.txt"],
        )

    release.write_text("continue", encoding="utf-8")
    deadline = time.monotonic() + 15
    current = first
    while current.get("status") == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
        current = execution.status(str(eng), first["execution_id"])

    assert current["status"] == "completed"
    assert output.read_text(encoding="utf-8") == "written by first command\n"
    assert _manifest_record(eng, first)["declared_evidence_outputs"] == [
        "evidence/recon/shared.txt"
    ]

    retry_deadline = time.monotonic() + 2
    while True:
        try:
            second = execution.execute(
                "write after the first execution released its output",
                argv=_write_file_argv(output, "written by second command\n"),
                eng_dir=str(eng),
                phase="recon",
                timeout_seconds=20,
                ptt_task_id="PT-001",
                evidence_outputs=["evidence/recon/shared.txt"],
            )
            break
        except ValueError as exc:
            if "already in use" not in str(exc) or time.monotonic() >= retry_deadline:
                raise
            time.sleep(0.02)
    assert second["status"] == "completed"
    assert output.read_text(encoding="utf-8") == "written by second command\n"


def test_a_byte_identical_rewrite_is_still_sealed_without_its_sibling(tmp_path):
    """#203 regression: bytes alone cannot tell a rewrite from an untouched file.

    A single command that rewrites an existing declared output with identical
    bytes leaves the content digest unchanged, so the file was dropped from the
    receipt and every finding citing it was rejected as unauthenticated — the
    exact proof loss the #203 narrowing was meant to prevent. The command did
    write the file, so it must be sealed; the untouched declared sibling still
    belongs to whoever produced it and must not be reattached.
    """
    eng = _engagement(tmp_path)
    rewritten = eng / "evidence" / "recon" / "rewritten.txt"
    untouched = eng / "evidence" / "recon" / "untouched.txt"
    untouched.parent.mkdir(parents=True)
    payload = "identical bytes\n"
    rewritten.write_text(payload, encoding="utf-8")
    untouched.write_text("from a batch-mate\n", encoding="utf-8")
    # Pin the baseline timestamp far in the past so any real write moves it,
    # independent of filesystem timestamp granularity.
    os.utime(rewritten, ns=(1_000_000_000, 1_000_000_000))
    baseline_mtime = rewritten.stat().st_mtime_ns
    baseline_digest = receipt_integrity.file_digest(rewritten)

    receipt = execution.execute(
        "python -c 'rewrite the output with identical bytes'",
        argv=_write_file_argv(rewritten, payload),
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=["evidence/recon/rewritten.txt", "evidence/recon/untouched.txt"],
    )

    assert rewritten.read_text(encoding="utf-8") == payload
    assert receipt_integrity.file_digest(rewritten) == baseline_digest
    assert rewritten.stat().st_mtime_ns != baseline_mtime
    assert _manifest_record(eng, receipt)["declared_evidence_outputs"] == [
        "evidence/recon/rewritten.txt"
    ]


def test_a_background_byte_identical_rewrite_is_sealed(tmp_path):
    """The background finalizer narrows on the same per-command provenance rule."""
    eng = _engagement(tmp_path)
    probe = eng / "evidence" / "recon" / "probe.txt"
    probe.parent.mkdir(parents=True)
    payload = "same bytes in the background\n"
    probe.write_text(payload, encoding="utf-8")
    os.utime(probe, ns=(1_000_000_000, 1_000_000_000))
    baseline_mtime = probe.stat().st_mtime_ns

    receipt = execution.execute(
        "python -c 'rewrite the background output with identical bytes'",
        argv=_write_file_argv(probe, payload),
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=30,
        ptt_task_id="PT-001",
        evidence_outputs=["evidence/recon/probe.txt"],
        background=True,
    )
    deadline = time.monotonic() + 15
    current = receipt
    while current.get("status") == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
        current = execution.status(str(eng), receipt["execution_id"])

    assert current["status"] == "completed"
    assert probe.read_text(encoding="utf-8") == payload
    assert probe.stat().st_mtime_ns != baseline_mtime
    assert _manifest_record(eng, receipt)["declared_evidence_outputs"] == [
        "evidence/recon/probe.txt"
    ]


def test_a_legacy_digest_baseline_still_narrows_by_content(tmp_path):
    """A record written before the snapshot shape keeps its content-only rule.

    Old manifests stored ``declared_outputs_before`` as a bare digest per file.
    Finishing such an in-flight record must not change how it narrows.
    """
    eng = _engagement(tmp_path)
    reported = eng / "evidence" / "recon" / "reported.txt"
    untouched = eng / "evidence" / "recon" / "untouched.txt"
    untouched.parent.mkdir(parents=True)
    reported.write_text("legacy rewritten\n", encoding="utf-8")
    untouched.write_text("from a batch-mate\n", encoding="utf-8")

    record = {
        "execution_id": "12345678-1234-4234-8234-123456789abc",
        "status": "running",
        "command": "legacy command",
        "phase": "recon",
        "declared_evidence_outputs": [
            "evidence/recon/reported.txt",
            "evidence/recon/untouched.txt",
        ],
        "declared_outputs_before": {
            "evidence/recon/reported.txt": "0" * 64,
            "evidence/recon/untouched.txt": receipt_integrity.file_digest(untouched),
        },
    }

    assert execution_support._produced_outputs(eng, record) == ["evidence/recon/reported.txt"]
