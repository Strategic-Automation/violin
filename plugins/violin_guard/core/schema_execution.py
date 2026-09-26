"""Execution and engagement lifecycle argument models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RebindPendingBatchArgsModel(BaseModel):
    """Explicitly rebind a completed pending batch to the sole active phase-compatible PTT task. This does not review or unlock the batch."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    batch_id: str
    current_task_id: str
    replacement_task_id: str
    note: str = Field(..., description="Operator reason for rebinding")
    confirm: bool = Field(..., description="Must be explicitly true")


class HeartbeatDoneArgsModel(BaseModel):
    """Call AFTER heartbeat review. Clear sequence: 1) violin_status -> 2) violin_review_batch (if pending batch exists) -> 3) violin_heartbeat_done(eng_dir=...)."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str = Field(..., description="Engagement directory")


class ExecArgsModel(BaseModel):
    """Authorize and execute one target command using any installed non-interactive Kali/Parrot CLI tool; there is no binary allowlist. Commands execute under POSIX shell (/bin/sh, dash on Debian/Ubuntu containers). Builtins like 'source' do not exist in POSIX shell ('source: not found'); use '. file.env' or 'export $(cat file.env)' / 'export $(grep -v "^#" file | xargs)' to load environment variables. Multi-command syntax (&&, ;) is supported, but bash-isms (source, [[ ]], <()) will fail. Requires one unambiguous [~] PTT task. Scope, phase, hypothesis, history, evidence, timeout, and sync gates still apply, and runtime requirements such as installation, root, hardware, services, GUI, or a TTY are not bypassed. The tool appends exact command history but never updates PTT progress. Hard BLOCK and sync_required never create a process."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    scope: str = ""
    phase: str
    command: str = Field(
        ..., description="Exact on-target command for any installed CLI executable"
    )
    target: str = Field(..., description="Explicit primary target host/IP/URL")
    session_id: str = ""
    backend: Literal["auto", "local", "docker"] = "auto"
    timeout_seconds: int = Field(180, ge=1, le=1800)
    cwd: str = Field("", description="Engagement-relative working directory")
    label: str = ""
    evidence_outputs: list[str] = Field(
        default_factory=list,
        description=(
            "Engagement-relative files beneath evidence/ that this command will create or "
            "update. The files the command actually writes are hashed into its signed "
            "execution receipt. Use this for scripts and tools that write evidence outside "
            "captured stdout/stderr."
        ),
    )
    background: bool = Field(
        False,
        description=(
            "Run as a tracked background process; use status/cancel for lifecycle management"
        ),
    )


class ExecBurstArgsModel(BaseModel):
    """Bounded command batch. Preflight denies the whole batch before execution when any command requires review, unless HERMES_YOLO_MODE=1; hard blocks are always denied. Requires one unambiguous [~] PTT task. Every completed command is appended to history automatically, but the executor never updates PTT progress. Review the batch once with violin_review_batch. Sync credit limits per phase apply (Recon: 10, Vuln Research: 10, Exploitation/Post-Exploitation/PRIVESC/FLAGS: 20 per sync window) and are shared across execution tools. If a burst is denied with 'insufficient sync credit for burst: need N, have M', split the command set into smaller bursts (size <= M) and review the batch via violin_review_batch to refresh sync credit. A burst is denied with 'skill receipt binding belongs to a different session' when session_id does not match the session that viewed the skill, so read the value from violin_status.skill.session_id instead of inventing a label. Use for recon and exploit/race batches; never raw terminal for targets."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str = Field(
        ...,
        description="engagement dir; enables one-time sync-lock arming on the last command",
    )
    phase: str = Field(
        ...,
        description="engagement phase: recon|vuln-research|exploitation|post-exploitation",
    )
    target: str = Field(..., description="Explicit primary target shared by the batch")
    commands: list[str] = Field(
        default_factory=list,
        description="inline newline-free commands, PRE-APPROVED AS A BATCH by the operator; preferred over commands_file",
    )
    commands_file: str = Field(
        "",
        description=(
            "optional engagement-relative path to a newline-delimited regular file; absolute, "
            "symlinked, and escaping paths are rejected"
        ),
    )
    scope: str = Field("", description="path to scope.yaml")
    session_id: str = Field(
        "",
        description=(
            "session bound to the skill-load gate; read it from "
            "violin_status.skill.session_id - a burst is denied when it differs from the "
            "session that viewed the skill"
        ),
    )
    label: str = Field("", description="optional batch label for logging")
    backend: Literal["auto", "local", "docker"] = "auto"
    timeout_seconds: int = Field(180, ge=1, le=1800)
    cwd: str = Field("", description="Engagement-relative working directory")
    continue_on_error: bool = False
    evidence_outputs: list[str] = Field(
        default_factory=list,
        description=(
            "engagement-relative evidence files this batch writes (same paths you would pass "
            "to violin_exec). Bursts are approved as one batch, so declare the union of the "
            "files the batch produces; each command's receipt then seals only the files that "
            "command itself wrote, so violin_submit_finding can authenticate them."
        ),
    )


class ExecStatusArgsModel(BaseModel):
    """Read the receipt for an execution owned by this engagement."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    execution_id: str


class ExecCancelArgsModel(BaseModel):
    """Cancel only the exact tracked process group for a running execution."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    execution_id: str


class TargetArgsModel(BaseModel):
    """Resolve the canonical in-scope target for the engagement from scope.yaml (kills hardcoded-IP fragility: a box reset just edits scope.yaml, not every command in history). Query by --host (in-scope IP/CIDR) or --role (named role from scope.yaml targets.roles, e.g. 'web'). Returns the ip/url/host field. The agent should run THIS to get the target, then interpolate the result into the actual command instead of hardcoding an IP."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str = Field(
        ..., description="engagement dir (required; target resolution is engagement-scoped)"
    )
    scope: str = Field("", description="explicit scope.yaml path (else $ENG_DIR/scope/scope.yaml)")
    host: str = Field("", description="in-scope IP/CIDR to resolve")
    role: str = Field("", description="named role from scope.yaml targets.roles (e.g. web)")
    field: Literal["ip", "url", "host"] = Field("ip", description="what to print (default ip)")


class StatusArgsModel(BaseModel):
    """Cheap one-shot explanation of the current task and phase, per-phase command requirements, pending batch commands, blockers, exact next actions, skill-load state, heartbeat state, and phase-aware sync credit. Mutates no state."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str = Field(
        ..., description="engagement dir ($ENG_DIR / $VIOLIN_ENG_ROOT env also honoured)"
    )
