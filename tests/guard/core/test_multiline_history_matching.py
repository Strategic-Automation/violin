import json
from pathlib import Path

from plugins.violin_guard import bootstrap, history, state
from plugins.violin_guard import handlers as service
from plugins.violin_guard.core.skill_receipts import (
    SkillViewResult,
    bind_task,
    complete_delivery,
    prepare_delivery,
)


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "eng"
    bootstrap.init_engagement(eng, host="10.10.10.10")
    scope = eng / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8").replace("confirmed: false", "confirmed: true"),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    return eng


def test_normalize_command_collapses_newlines_and_whitespace() -> None:
    multiline = "cd /app\n  mkdir -p build \n  echo 'hello world'\n"
    normalized = history.normalize_command(multiline)
    assert normalized == "cd /app mkdir -p build echo 'hello world'"


def test_append_history_sanitizes_multiline_commands(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    multiline = "cd /var/www\ncurl -s http://example.com\nhead -n 10 index.html"
    history.append_history(eng, multiline, "RECON", 0, "evidence/executions/test.json")

    hist_file = eng / "state" / "history.md"
    assert hist_file.exists()
    record_lines = [
        line for line in hist_file.read_text(encoding="utf-8").splitlines() if line.startswith("- ")
    ]
    assert len(record_lines) == 1  # Formatted as single line in history.md
    assert "cd /var/www curl -s http://example.com head -n 10 index.html" in record_lines[0]


def test_history_contains_matches_multiline_and_whitespace_variants(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    multiline_cmd = "cd /home/kali\n  mkdir -p output\n  curl http://eloquia.htb/"
    history.append_history(eng, multiline_cmd, "RECON", 0, "evidence/executions/1.json")

    # Match exact multiline input string
    assert history.history_contains(eng, multiline_cmd)

    # Match normalized single-line representation
    single_line_cmd = "cd /home/kali mkdir -p output curl http://eloquia.htb/"
    assert history.history_contains(eng, single_line_cmd)

    # Match string with extra newlines/tabs
    variant_cmd = "cd /home/kali\n\tmkdir -p output\n\tcurl http://eloquia.htb/\n"
    assert history.history_contains(eng, variant_cmd)


def test_history_contains_returns_false_when_not_in_history(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    multiline_cmd = "echo 'start'\ncat /etc/passwd\necho 'done'"

    # Clear history.md
    hist_file = eng / "state" / "history.md"
    if hist_file.exists():
        hist_file.write_text("# History\n", encoding="utf-8")

    assert not history.history_contains(eng, multiline_cmd)


def test_batch_review_succeeds_for_multiline_pending_command(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    state.record_session_id(eng, "multiline-session")
    reservation = prepare_delivery(
        eng,
        session_id="multiline-session",
        skill="pentest",
        bundle_digest="sha256:" + "a" * 64,
        phase="RECON",
    )
    if reservation.owner:
        reservation = complete_delivery(eng, reservation, SkillViewResult(True, content="pentest"))
    bind_task(eng, task_id="PT-010", delivery_id=reservation.id, technique="recon")
    multiline_cmd = "cd /app\n  curl -i http://eloquia.htb/\n  wc -l index.html"

    # Mark pending sync with multiline command
    state.mark_pending_sync(eng, multiline_cmd, "RECON", "PT-010")
    pending = state.get_pending_sync(eng)
    assert pending is not None

    # Record history
    history.append_history(eng, multiline_cmd, "RECON", 0, "evidence/executions/test.json")

    # Service batch review must succeed without throwing history validation error
    result = json.loads(
        service.handle_review_batch(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[x]",
                "note": "Reviewed multiline batch successfully",
            }
        )
    )
    assert result.get("status") == "ok"
    assert result.get("released") is True
    assert state.get_pending_sync(eng) is None
