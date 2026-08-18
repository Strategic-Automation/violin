"""Typed tool schemas for the violin-guard plugin using Pydantic v2."""

from __future__ import annotations

from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from . import state

# ---------------------------------------------------------------------------
# Pydantic v2 Models
# ---------------------------------------------------------------------------


class RecordPttArgsModel(BaseModel):
    """Start one untouched [ ] PTT task with [~], or review the active task after a completed batch. A non-empty note is required; reviewed batches are bound automatically."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    id: str
    status: str = Field(
        "",
        description=(
            "Task lifecycle status token: '[~]' (active/start), '[x]' (completed), "
            "'[-]' (cancelled), '[!]' (blocked). Must be a literal bracket token (not 'in_progress')."
        ),
    )
    note: str = ""
    skill: str = Field(..., description="Selected Violin skill required before task activation")
    technique: str = Field(..., description="Concrete technique required before task activation")
    hypothesis_id: str = Field("", description="Required for hypothesis-driven phases")
    outcome: str = ""
    evidence_paths: list[str] = Field(default_factory=list)
    next_action: str = ""
    next_technique: str = ""
    research_attempted: bool = False
    title: str = Field("", description="Required when explicitly creating a new PTT task")
    phase: str = Field("", description="Phase for an explicitly created PTT task")


class RecordHypothesisArgsModel(BaseModel):
    """Record or update a hypothesis row in the engagement state."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    service: str = ""
    port: str = ""
    id: str = ""
    title: str = ""
    status: str = Field(
        "",
        description=(
            "Canonical status: 'Candidate', 'Likely', 'Validated', or 'Rejected'. "
            "When status='Validated', 'runtime_evidence' is required (path under evidence/). "
            "When status='Rejected', 'verification_status' ('syntax_confirmed' or 'not_implemented'), "
            "'test_command', 'test_response', and 'rejection_reason' are required."
        ),
    )
    confidence: str = Field("", description="0.1-1.0 guesstimate; escalate only with evidence")
    timebox: str = Field("", description="e.g. 4 tool batches or 30 min — then re-evaluate")
    cheapest_test: str = Field(
        "", description="Single cheapest probe that discriminates this theory"
    )
    phase: str = ""
    target: str = Field("", description="target host/IP (must be in scope)")
    vuln_class: str = ""
    rationale: str = ""
    evidence: str = ""
    cve_research: str = Field(
        "",
        description=(
            "Required before exploitation: online CVE/advisory query, source, and outcome. Truthful"
            " no-results/not-applicable/unavailable outcomes are allowed."
        ),
    )
    exploit_research: str = Field(
        "",
        description=(
            "Required before exploitation: online PoC/exploit query, source, and outcome. Truthful"
            " no-results/unavailable outcomes are allowed."
        ),
    )
    test_command: str = Field("", description="Exact syntax tested, including argument order")
    test_response: str = Field("", description="Exact decisive response or error")
    verification_status: str = Field(
        "",
        description=(
            "Required when status='Rejected': must be 'syntax_confirmed' or 'not_implemented'. "
            "Use 'syntax_uncertain' or 'not_tested' to keep hypothesis active for re-testing."
        ),
    )
    kill_criteria: str = Field(
        "",
        description="Evidence that contradicts, or no new info in N batches — then kill & log in Decoy Trail",
    )
    rejection_reason: str = Field(
        "", description="Why a rejected hypothesis is safe to stop pursuing"
    )
    next_step: str = ""
    linked_findings: str = ""
    candidate_source: str = Field(
        "",
        description=(
            "Optional normalized source route: domain, osint, public-records, username, identity, "
            "repository, supply-chain, codebase, source, semgrep, codeql, or sarif. "
            "When present, it can select the PTT skill unless vuln_class has a higher-priority route."
        ),
    )
    entry_point: str = ""
    data_flow: str = ""
    source_evidence: str = ""
    runtime_evidence: str = Field(
        "",
        description=(
            "Required when status is Validated. Path to runtime execution receipt or evidence file "
            "(e.g. evidence/executions/001-command.json, evidence/exploitation/poc.txt)."
        ),
    )


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
    background: bool = Field(
        False,
        description=(
            "Run as a tracked background process; use status/cancel for lifecycle management"
        ),
    )


class FindingModel(BaseModel):
    """Optional structured finding derived only from this batch."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field("", description="Optional FIND-NNN id")
    hypothesis_id: str = Field(..., description="Validated linked hypothesis")
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    description: str
    impact: str
    remediation: str


class ReviewBatchArgsModel(BaseModel):
    """Review the current completed batch, optionally create one receipt-backed finding, and release the sync lock. The active PTT task stays active unless status='[x]' is explicitly requested. All inputs are validated before mutation; the lock clears last."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    id: str = Field(..., description="Active PTT task id")
    status: str = Field(
        "[~]",
        description=(
            "PTT status after review. Defaults to '[~]' so continued same-phase work keeps the "
            "same task; use '[x]' only when deliberately closing it."
        ),
    )
    note: str = Field(..., description="Truthful result/evidence review")
    skill: str = Field(
        "",
        description="Review skill; defaults to the active execution binding (or fp-check if specified)",
    )
    hypothesis_id: str = Field("", description="Required for hypothesis-driven phases")
    outcome: str = ""
    evidence_paths: list[str] = Field(default_factory=list)
    next_action: str = ""
    next_technique: str = ""
    research_attempted: bool = False
    finding: FindingModel | None = Field(
        None, description="Optional structured finding derived only from this batch"
    )


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


class ExecBurstArgsModel(BaseModel):
    """Single-approval bounded command batch. Requires one unambiguous [~] PTT task. Every completed command is appended to history automatically, but the executor never updates PTT progress. Review the batch once with violin_review_batch. Sync credit limits per phase apply (Recon: 10, Vuln Research: 10, Exploitation/Post-Exploitation/PRIVESC/FLAGS: 20 per sync window) and are shared across execution tools. If a burst is denied with 'insufficient sync credit for burst: need N, have M', split the command set into smaller bursts (size <= M) and review the batch via violin_review_batch to refresh sync credit. Use for recon and exploit/race batches; never raw terminal for targets."""

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
    session_id: str = Field("", description="session/goal label for skill-load gating")
    label: str = Field("", description="optional batch label for logging")
    backend: Literal["auto", "local", "docker"] = "auto"
    timeout_seconds: int = Field(180, ge=1, le=1800)
    cwd: str = Field("", description="Engagement-relative working directory")
    continue_on_error: bool = False


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


# ---------------------------------------------------------------------------
# Validation & Dynamic Tool Schema Generation
# ---------------------------------------------------------------------------


T = TypeVar("T", bound=BaseModel)


def validate_args(model_cls: type[T], raw_args: dict[str, Any] | None, *, strict: bool = True) -> T:
    """Validate raw payload dictionary using Pydantic model."""
    return model_cls.model_validate(raw_args or {}, strict=strict)


def to_tool_schema(
    model_cls: type[BaseModel],
    description: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Dynamically export tool schema directly from Pydantic model_json_schema()."""
    schema = model_cls.model_json_schema()
    model_description = schema.pop("description", "")
    doc = description or model_description or (model_cls.__doc__ or "")
    schema.pop("title", None)

    if "properties" in schema:
        for prop in schema["properties"].values():
            if isinstance(prop, dict):
                prop.pop("title", None)

    res: dict[str, Any] = {"description": doc, "parameters": schema}
    if name:
        res["name"] = name
    return res


# Dynamic Tool Schemas (Derived directly from Pydantic models via native model_json_schema)

RECORD_PTT_SCHEMA = to_tool_schema(RecordPttArgsModel)
RECORD_HYPOTHESIS_SCHEMA = to_tool_schema(RecordHypothesisArgsModel)
EXEC_SCHEMA = to_tool_schema(ExecArgsModel)
REVIEW_BATCH_SCHEMA = to_tool_schema(ReviewBatchArgsModel)
REBIND_PENDING_BATCH_SCHEMA = to_tool_schema(RebindPendingBatchArgsModel)
HEARTBEAT_DONE_SCHEMA = to_tool_schema(
    HeartbeatDoneArgsModel,
    description=(
        f"Call AFTER heartbeat review. Required clear sequence: 1) violin_status -> 2) violin_review_batch "
        f"(if pending batch exists) -> 3) violin_heartbeat_done(eng_dir=...). Re-read skills/pentest/SKILL.md "
        f"and review scope.yaml / state/ptt.md / hypotheses.md / state/history.md. Cadence is {state.COMMAND_INTERVAL}"
        " executed target commands; exploitation/post-exploitation/PRIVESC/FLAGS suppress"
        " heartbeat. Clears heartbeat lock so violin_exec may release the next command."
    ),
)
EXEC_BURST_SCHEMA = to_tool_schema(ExecBurstArgsModel, name="violin_exec_burst")
EXEC_STATUS_SCHEMA = to_tool_schema(ExecStatusArgsModel)
EXEC_CANCEL_SCHEMA = to_tool_schema(ExecCancelArgsModel)
TARGET_SCHEMA = to_tool_schema(TargetArgsModel, name="violin_target")
STATUS_SCHEMA = to_tool_schema(StatusArgsModel, name="violin_status")
