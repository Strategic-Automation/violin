"""Regression tests for exact command deduplication."""

from pathlib import Path

from plugins.violin_guard.core.evidence.history import (
    append_history,
    check_history_staleness,
    history_contains,
)


def test_history_deduplication_compares_the_recorded_command_field(tmp_path: Path) -> None:
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    for suffix in ("", " | receipt=evidence/executions/test.json"):
        history.write_text(
            f"- 2026-07-14T10:00:00Z | phase=RECON | exit_code=0 | command=echo done{suffix}\n",
            encoding="utf-8",
        )

        errors, _, _ = check_history_staleness(tmp_path, "echo")
        assert not errors

        errors, _, _ = check_history_staleness(tmp_path, "echo done")
        assert errors


def test_written_history_uses_command_length_for_unambiguous_receipt_parsing(
    tmp_path: Path,
) -> None:
    command = "printf 'value | receipt=fake | command_length=1'"
    append_history(tmp_path, command, "RECON", 0, "evidence/executions/test.json")

    errors, _, _ = check_history_staleness(tmp_path, command)
    assert errors
    assert history_contains(tmp_path, command)

    errors, _, infos = check_history_staleness(tmp_path, command, allow_pending_repeat=True)
    assert not errors
    assert any("pending batch" in info for info in infos)


def test_malformed_history_line_does_not_create_a_false_repeat(tmp_path: Path) -> None:
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    history.write_text("previous command: echo done\n", encoding="utf-8")

    errors, _, _ = check_history_staleness(tmp_path, "echo done")
    assert not errors


def test_exact_repeat_after_a_failed_run_is_allowed(tmp_path: Path) -> None:
    """A re-run after a failed attempt is legitimate, not drift.

    Denying it forces a cosmetic edit to the command, which wastes a round trip
    and contaminates the execution receipts with probes that were only ever
    varied to satisfy the dedup check.
    """
    command = "curl -o evidence/recon/tech.json https://shop.example.test/openapi.json"
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    history.write_text(
        "- 2026-07-14T10:00:00Z | phase=RECON | exit_code=23 | status=failed"
        f" | command={command}\n",
        encoding="utf-8",
    )

    errors, _, infos = check_history_staleness(tmp_path, command)
    assert not errors, errors
    assert any("did not complete successfully" in info for info in infos), infos


def test_exact_repeat_after_a_successful_run_is_still_rejected(tmp_path: Path) -> None:
    command = "nmap -sV 10.10.10.10"
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    history.write_text(
        "- 2026-07-14T10:00:00Z | phase=RECON | exit_code=0 | status=completed"
        f" | command={command}\n",
        encoding="utf-8",
    )

    errors, _, infos = check_history_staleness(tmp_path, command)
    assert errors, "a repeat after a successful run is still drift"
    assert not infos
