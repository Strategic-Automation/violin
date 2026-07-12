"""Typed tool schemas for the violin-guard plugin."""

CHECK_COMMAND_SCHEMA = {
    "description": "Run a check-command gate (typed wrapper over violin_guard.py check-command).",
    "parameters": {
        "type": "object",
        "properties": {
            "scope": {"type": "string"},
            "eng_dir": {"type": "string"},
            "phase": {"type": "string"},
            "command": {"type": "string"},
            "session_id": {"type": "string"},
            "skill_loaded_file": {"type": "string"},
        },
        "required": ["eng_dir", "phase", "command"],
        "additionalProperties": False,
    },
}

RECORD_PTT_SCHEMA = {
    "description": "Update a PTT row (status/note).",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "id": {"type": "string"},
            "status": {"type": "string"},
            "note": {"type": "string"},
        },
        "required": ["eng_dir", "id"],
        "additionalProperties": False,
    },
}

RECORD_HYPOTHESIS_SCHEMA = {
    "description": "Record/update a hypothesis row (delegates to scripts/hypothesis_guard.py record-hypothesis).",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "service": {"type": "string"},
            "port": {"type": "string"},
            "id": {"type": "string"},
            "title": {"type": "string"},
            "status": {"type": "string"},
            "phase": {"type": "string"},
            "vuln_class": {"type": "string"},
            "rationale": {"type": "string"},
            "evidence": {"type": "string"},
        },
        "required": ["eng_dir", "service", "port"],
        "additionalProperties": True,
    },
}

RECORD_HISTORY_SCHEMA = {
    "description": "Append a command to state/history.md (proves continuity).",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "command": {"type": "string"},
            "exit_code": {"type": "integer"},
            "phase": {"type": "string"},
        },
        "required": ["eng_dir", "command"],
        "additionalProperties": False,
    },
}

EXEC_SCHEMA = {
    "description": "FORCED-GATE execution path. Re-runs check-command internally; refuses to return an executable command if the gate BLOCKs OR if a prior command's artifacts (ptt.md/history.md/hypothesis-board.md) are not yet updated. Use this instead of raw terminal for any target-touching command.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "scope": {"type": "string"},
            "phase": {"type": "string"},
            "command": {"type": "string", "description": "Exact on-target command"},
            "session_id": {"type": "string"},
            "skill_loaded_file": {"type": "string"},
        },
        "required": ["eng_dir", "scope", "phase", "command"],
        "additionalProperties": False,
    },
}

SYNC_DONE_SCHEMA = {
    "description": "Call AFTER updating ptt.md / state/history.md / hypothesis-board.md for the last approved command. Verifies the artifacts are fresh, then unlocks the next violin_exec call. Mandatory before the next target command.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string", "description": "Engagement directory"},
        },
        "required": ["eng_dir"],
        "additionalProperties": False,
    },
}

HEARTBEAT_DONE_SCHEMA = {
    "description": "Call AFTER reviewing the engagement files (scope.yaml / ptt.md / hypotheses.md / history.md) on the periodic cadence (every 5 target commands, or 10 messages if violin_message_tick is used). Clears the heartbeat-pending lock so violin_exec may release the next command. Mandatory once a heartbeat review is due.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string", "description": "Engagement directory"},
        },
        "required": ["eng_dir"],
        "additionalProperties": False,
    },
}

MESSAGE_TICK_SCHEMA = {
    "description": "LLM-opt-in message counter. Call ONCE per assistant message during an engagement. Every 10 messages it sets a heartbeat-pending lock (reinforcing the 5-command gate) so the next violin_exec requires violin_heartbeat_done. Returns the running message count.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string", "description": "Engagement directory"},
        },
        "required": ["eng_dir"],
        "additionalProperties": False,
    },
}

