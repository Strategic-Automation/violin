"""Typed tool schemas for the violin-guard plugin.

Model-visible contracts only — no implementation logic.
"""

from __future__ import annotations

from . import state

CHECK_COMMAND_SCHEMA = {
    "description": "Run a check-command gate (typed wrapper over violin_guard.py check-command).",
    "parameters": {
        "type": "object",
        "properties": {
            "scope": {"type": "string"},
            "eng_dir": {"type": "string"},
            "phase": {"type": "string"},
            "command": {"type": "string"},
            "target": {"type": "string", "description": "Explicit primary target host/IP/URL"},
            "session_id": {"type": "string"},
        },
        "required": ["eng_dir", "phase", "command", "target"],
        "additionalProperties": False,
    },
}

RECORD_PTT_SCHEMA = {
    "description": "Start one untouched [ ] PTT task with [~], or review the active task after a completed batch. A non-empty note is required; reviewed batches are bound automatically.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "id": {"type": "string"},
            "status": {"type": "string"},
            "note": {"type": "string"},
            "skill": {"type": "string", "description": "Required selected Violin skill"},
            "technique": {
                "type": "string",
                "description": "Required concrete technique for this task",
            },
            "hypothesis_id": {
                "type": "string",
                "description": "Required for hypothesis-driven phases",
            },
            "title": {
                "type": "string",
                "description": "Required when explicitly creating a new PTT task",
            },
            "phase": {"type": "string", "description": "Phase for an explicitly created PTT task"},
        },
        "required": ["eng_dir", "id"],
        "additionalProperties": False,
    },
}

RECORD_HYPOTHESIS_SCHEMA = {
    "description": "Record or update a hypothesis row in the engagement state.",
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
            "target": {"type": "string", "description": "target host/IP (must be in scope)"},
            "vuln_class": {"type": "string"},
            "rationale": {"type": "string"},
            "evidence": {"type": "string"},
            "cve_research": {
                "type": "string",
                "description": "Required before exploitation: online CVE/advisory query, source, and outcome. Truthful no-results/not-applicable/unavailable outcomes are allowed.",
            },
            "exploit_research": {
                "type": "string",
                "description": "Required before exploitation: online PoC/exploit query, source, and outcome. Truthful no-results/unavailable outcomes are allowed.",
            },
            "test_command": {
                "type": "string",
                "description": "Exact syntax tested, including argument order",
            },
            "test_response": {"type": "string", "description": "Exact decisive response or error"},
            "verification_status": {
                "type": "string",
                "enum": ["syntax_confirmed", "syntax_uncertain", "not_implemented", "not_tested"],
            },
            "rejection_reason": {
                "type": "string",
                "description": "Why a rejected hypothesis is safe to stop pursuing",
            },
        },
        "required": ["eng_dir"],
        "additionalProperties": True,
    },
}

EXEC_SCHEMA = {
    "description": "Authorize and execute one target command using any installed non-interactive Kali/Parrot CLI tool; there is no binary allowlist. Requires one unambiguous [~] PTT task. Scope, phase, hypothesis, history, evidence, timeout, and sync gates still apply, and runtime requirements such as installation, root, hardware, services, GUI, or a TTY are not bypassed. The tool appends exact command history but never updates PTT progress. Hard BLOCK and sync_required never create a process.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "scope": {"type": "string"},
            "phase": {"type": "string"},
            "command": {
                "type": "string",
                "description": "Exact on-target command for any installed CLI executable",
            },
            "target": {"type": "string", "description": "Explicit primary target host/IP/URL"},
            "session_id": {"type": "string"},
            "backend": {"type": "string", "enum": ["auto", "local", "docker"], "default": "auto"},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1800},
            "cwd": {"type": "string", "description": "Engagement-relative working directory"},
            "label": {"type": "string"},
            "background": {
                "type": "boolean",
                "default": False,
                "description": "Run as a tracked background process; use status/cancel for lifecycle management",
            },
        },
        "required": ["eng_dir", "phase", "command", "target"],
        "additionalProperties": False,
    },
}

REVIEW_BATCH_SCHEMA = {
    "description": "Review the current completed batch, optionally create one receipt-backed finding, update the active PTT task, and release the sync lock. All inputs are validated before mutation; the lock clears last.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "id": {"type": "string", "description": "Active PTT task id"},
            "status": {
                "type": "string",
                "enum": ["[~]", "[x]", "[!]", "[-]"],
            },
            "note": {"type": "string", "description": "Truthful result/evidence review"},
            "skill": {"type": "string", "description": "Required selected review skill"},
            "hypothesis_id": {
                "type": "string",
                "description": "Required for hypothesis-driven phases",
            },
            "finding": {
                "type": "object",
                "description": "Optional structured finding derived only from this batch",
                "properties": {
                    "finding_id": {"type": "string", "description": "Optional FIND-NNN id"},
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    },
                    "description": {"type": "string"},
                    "impact": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": ["title", "severity", "description", "impact", "remediation"],
                "additionalProperties": False,
            },
        },
        "required": ["eng_dir", "id", "status", "note"],
        "additionalProperties": False,
    },
}

REBIND_PENDING_BATCH_SCHEMA = {
    "description": "Explicitly rebind a completed pending batch to the sole active phase-compatible PTT task. This does not review or unlock the batch.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "batch_id": {"type": "string"},
            "current_task_id": {"type": "string"},
            "replacement_task_id": {"type": "string"},
            "note": {"type": "string", "description": "Operator reason for rebinding"},
            "confirm": {"type": "boolean", "description": "Must be explicitly true"},
        },
        "required": [
            "eng_dir",
            "batch_id",
            "current_task_id",
            "replacement_task_id",
            "note",
            "confirm",
        ],
        "additionalProperties": False,
    },
}

HEARTBEAT_DONE_SCHEMA = {
    "description": f"Call AFTER heartbeat review: re-read skills/pentest/SKILL.md and review scope.yaml / state/ptt.md / hypotheses.md / state/history.md. Cadence is {state.COMMAND_INTERVAL} executed target commands; exploitation/post-exploitation/PRIVESC/FLAGS suppress heartbeat. Clears heartbeat lock so violin_exec may release the next command.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string", "description": "Engagement directory"},
        },
        "required": ["eng_dir"],
        "additionalProperties": False,
    },
}

EXEC_BURST_SCHEMA = {
    "name": "violin_exec_burst",
    "description": "Single-approval bounded command batch. Requires one unambiguous [~] PTT task. Every completed command is appended to history automatically, but the executor never updates PTT progress. Review the batch once with violin_review_batch. Use for recon and exploit/race batches; never raw terminal for targets.",
    "parameters": {
        "type": "object",
        "properties": {
            "commands": {
                "type": "array",
                "items": {"type": "string"},
                "description": "inline newline-free commands, PRE-APPROVED AS A BATCH by the operator; preferred over commands_file",
            },
            "commands_file": {
                "type": "string",
                "description": "optional path to a newline-delimited file of commands",
            },
            "scope": {"type": "string", "description": "path to scope.yaml"},
            "target": {
                "type": "string",
                "description": "Explicit primary target shared by the batch",
            },
            "phase": {
                "type": "string",
                "description": "engagement phase: recon|vuln-research|exploitation|post-exploitation",
            },
            "eng_dir": {
                "type": "string",
                "description": "engagement dir; enables one-time sync-lock arming on the last command",
            },
            "session_id": {
                "type": "string",
                "description": "session/goal label for skill-load gating",
            },
            "label": {"type": "string", "description": "optional batch label for logging"},
            "backend": {"type": "string", "enum": ["auto", "local", "docker"], "default": "auto"},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1800},
            "cwd": {"type": "string", "description": "Engagement-relative working directory"},
            "continue_on_error": {"type": "boolean", "default": False},
        },
        "required": ["eng_dir", "phase", "target"],
    },
}

EXEC_STATUS_SCHEMA = {
    "description": "Read the receipt for an execution owned by this engagement.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "execution_id": {"type": "string"},
        },
        "required": ["eng_dir", "execution_id"],
        "additionalProperties": False,
    },
}

EXEC_CANCEL_SCHEMA = {
    "description": "Cancel only the exact tracked process group for a running execution.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "execution_id": {"type": "string"},
        },
        "required": ["eng_dir", "execution_id"],
        "additionalProperties": False,
    },
}

SEARCH_EXPLOIT_SCHEMA = {
    "description": "Search the local ExploitDB index without downloading or executing candidates.",
    "parameters": {
        "type": "object",
        "properties": {
            "product": {"type": "string"},
            "version": {"type": "string"},
            "service": {"type": "string"},
            "cve": {"type": "string"},
        },
        "additionalProperties": False,
    },
}

_ADAPTER_COMMON = {
    "eng_dir": {"type": "string"},
    "scope": {"type": "string"},
    "phase": {"type": "string"},
    "target": {"type": "string"},
    "session_id": {"type": "string"},
    "backend": {"type": "string", "enum": ["auto", "local", "docker"], "default": "auto"},
    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1800},
    "cwd": {"type": "string"},
    "label": {"type": "string"},
    "extra_args": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
}


HTTPX_SCHEMA = {
    "description": "Run typed HTTP probing through violin_exec.",
    "parameters": {
        "type": "object",
        "properties": _ADAPTER_COMMON,
        "required": ["eng_dir", "phase", "target"],
        "additionalProperties": False,
    },
}

NUCLEI_SCHEMA = {
    "description": "Run a typed nuclei scan through violin_exec; scanner output remains unconfirmed evidence.",
    "parameters": {
        "type": "object",
        "properties": {
            **_ADAPTER_COMMON,
            "templates": {"type": "string"},
            "severity": {"type": "string"},
        },
        "required": ["eng_dir", "phase", "target"],
        "additionalProperties": False,
    },
}

FFUF_SCHEMA = {
    "description": "Run typed ffuf content discovery through violin_exec.",
    "parameters": {
        "type": "object",
        "properties": {
            **_ADAPTER_COMMON,
            "url": {"type": "string"},
            "wordlist": {"type": "string"},
            "headers": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["eng_dir", "phase", "url", "wordlist"],
        "additionalProperties": False,
    },
}

LISTENER_SCHEMA = {
    "description": "Start a tracked local netcat listener with deterministic flags for a known implementation.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {"type": "string"},
            "scope": {"type": "string"},
            "phase": {"type": "string"},
            "target": {"type": "string", "description": "In-scope assessment target"},
            "session_id": {"type": "string"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "bind_host": {"type": "string"},
            "keep_open": {"type": "boolean", "default": False},
            "binary": {"type": "string", "default": "nc"},
            "variant": {
                "type": "string",
                "enum": ["openbsd", "traditional", "ncat"],
                "description": "Optional known variant; otherwise detected once from binary help/version output",
            },
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1800},
            "cwd": {"type": "string"},
            "label": {"type": "string"},
        },
        "required": ["eng_dir", "phase", "target", "port"],
        "additionalProperties": False,
    },
}

TARGET_SCHEMA = {
    "name": "violin_target",
    "description": "Resolve the canonical in-scope target for the engagement from scope.yaml (kills hardcoded-IP fragility: a box reset just edits scope.yaml, not every command in history). Query by --host (in-scope IP/CIDR) or --role (named role from scope.yaml targets.roles, e.g. 'web'). Returns the ip/url/host field. The agent should run THIS to get the target, then interpolate the result into the actual command instead of hardcoding an IP.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {
                "type": "string",
                "description": "engagement dir (required; target resolution is engagement-scoped)",
            },
            "scope": {
                "type": "string",
                "description": "explicit scope.yaml path (else $ENG_DIR/scope/scope.yaml)",
            },
            "host": {"type": "string", "description": "in-scope IP/CIDR to resolve"},
            "role": {
                "type": "string",
                "description": "named role from scope.yaml targets.roles (e.g. web)",
            },
            "field": {
                "type": "string",
                "enum": ["ip", "url", "host"],
                "description": "what to print (default ip)",
            },
        },
        "required": ["eng_dir"],
    },
}

STATUS_SCHEMA = {
    "name": "violin_status",
    "description": "Cheap one-shot explanation of the current task and phase, per-phase command requirements, pending batch commands, blockers, exact next actions, skill-load state, heartbeat state, and phase-aware sync credit. Mutates no state.",
    "parameters": {
        "type": "object",
        "properties": {
            "eng_dir": {
                "type": "string",
                "description": "engagement dir ($ENG_DIR / $VIOLIN_ENG_ROOT env also honoured)",
            },
        },
        "required": ["eng_dir"],
        "additionalProperties": False,
    },
}
