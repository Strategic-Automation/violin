"""Unit tests verifying framework feedback documentation clarifications in tool schemas."""

from plugins.violin_guard import schemas


def test_exec_schema_posix_shell_guidance():
    desc = schemas.EXEC_SCHEMA["description"]
    assert "POSIX shell" in desc
    assert "/bin/sh" in desc
    assert "source: not found" in desc
    assert ". file.env" in desc


def test_exec_burst_schema_sync_credit_guidance():
    desc = schemas.EXEC_BURST_SCHEMA["description"]
    assert "Sync credit" in desc or "sync credit" in desc
    assert "insufficient sync credit" in desc
    assert "violin_review_batch" in desc


def test_heartbeat_done_schema_clearance_sequence():
    desc = schemas.HEARTBEAT_DONE_SCHEMA["description"]
    assert "violin_status" in desc
    assert "violin_review_batch" in desc
    assert "violin_heartbeat_done" in desc


def test_record_hypothesis_schema_guidance_hints():
    props = schemas.RECORD_HYPOTHESIS_SCHEMA["parameters"]["properties"]
    status_desc = props["status"]["description"]
    assert "Validated" in status_desc
    assert "runtime_evidence" in status_desc
    assert "Rejected" in status_desc
    verification_desc = props["verification_status"]["description"]
    assert "syntax_confirmed" in verification_desc
    assert "not_implemented" in verification_desc


def test_terminal_policy_block_message_mentions_typed_tools():
    from plugins.violin_guard.gates.terminal_policy import block_terminal_command

    msg = block_terminal_command("nslookup 10.10.10.10")
    assert msg is not None
    assert "violin_exec" in msg
    assert "violin_exec_burst" in msg
