"""Regression tests for redacted tool records versus raw evidence files."""

from __future__ import annotations

import sys
from pathlib import Path

from plugins.violin_guard.core.engagement import bootstrap, ptt
from plugins.violin_guard.engine import execution
from tests.guard.receipt_fixture import bind_active_task


def test_declared_evidence_file_preserves_original_http_bytes(tmp_path: Path) -> None:
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    ptt_file = eng / "state" / "ptt.md"
    ptt_file.write_text(
        ptt_file.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng)
    active_task = ptt.find_active_task(ptt.parse_ptt(eng / "state" / "ptt.md"))
    assert active_task is not None

    body = b"abc"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 3\r\n"
        b"Authorization: Bearer inert-redaction-fixture\r\n\r\n" + body
    )
    evidence_path = eng / "evidence" / "recon" / "response.txt"
    writer = (
        "from pathlib import Path; import sys; "
        "path = Path(sys.argv[1]); path.parent.mkdir(parents=True, exist_ok=True); "
        "path.write_bytes(sys.argv[2].encode('ascii'))"
    )

    result = execution.execute(
        "python local evidence fixture",
        eng_dir=str(eng),
        phase=active_task.phase,
        backend="local",
        argv=[sys.executable, "-c", writer, str(evidence_path), response.decode("ascii")],
        evidence_outputs=["evidence/recon/response.txt"],
        ptt_task_id=active_task.id,
        timeout_seconds=10,
    )

    assert result["executed"] is True
    saved = evidence_path.read_bytes()
    assert saved == response
    headers, saved_body = saved.split(b"\r\n\r\n", maxsplit=1)
    content_length = next(
        int(line.split(b":", maxsplit=1)[1])
        for line in headers.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    assert len(saved_body) == content_length
    assert b"Authorization: Bearer inert-redaction-fixture" in saved
