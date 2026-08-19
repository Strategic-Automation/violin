"""Check-command sub-guards orchestrator and pipeline.

This is the canonical command, freshness, and closeout policy implementation.
No subprocess calls — pure functions returning dataclasses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..core import bootstrap, ptt, state
from ..core import history as history_mod
from ..core.phases import Phase, normalize_phase, suppresses_heartbeat
from ..core.results import GuardResult
from ..core.targets import (
    check_scope_targets,
    is_research_host,
    normalize_target,
)
from .hypothesis_gate import (
    _RECORD_AS_YOU_GO_GRACE,
    HypothesisResult,
    check_cross_engagement_paths,
    check_destructive_patterns,
    check_http_proof_flags,
    check_hypothesis_freshness,
    check_local_artifact_paths,
    check_skill_binding,
)
from .scope_gate import (
    ScopeResult,
    accepted_action_aliases,
    check_scope_authorization,
    map_scope_actions,
    validate_scope,
)


@dataclass
class CheckCommandArgs:
    command: str
    phase: str
    eng_dir: str
    scope: str = ""
    target: str | None = None
    session_id: str | None = None
    account_sync: bool = True
    hypothesis_id: str | None = None


@dataclass
class CheckResult(GuardResult):
    def print(self) -> None:
        for error in self.errors:
            print(f"BLOCK: {error}")
        for warning in self.warnings:
            print(f"REVIEW: {warning}")
        for info in self.infos:
            print(f"OK: {info}")


def check_command(args: CheckCommandArgs) -> CheckResult:
    """Run all command validation checks and return a unified CheckResult."""
    result = CheckResult()

    # 1. Phase validation
    try:
        phase = normalize_phase(args.phase)
    except ValueError as exc:
        result.add_error(str(exc))
        return result

    # 2. Scope checks
    eng_dir = state.resolve_eng_dir(args.eng_dir)
    canonical_scope_path = (eng_dir / "scope" / "scope.yaml").resolve()
    requested_scope_path = (
        Path(args.scope).expanduser().resolve() if args.scope else canonical_scope_path
    )
    scope_path = canonical_scope_path

    if requested_scope_path != canonical_scope_path:
        result.add_error(
            "runtime execution must use the engagement's canonical scope.yaml; "
            "validate alternate scope files separately with validate-scope"
        )

    # 1. Bootstrap completeness
    bootstrap_result = bootstrap.check_bootstrap(str(eng_dir), auto_repair=False)
    result.errors.extend(bootstrap_result.errors)
    result.warnings.extend(bootstrap_result.warnings)
    result.infos.extend(bootstrap_result.infos)

    # 2. Scope validation
    scope_result = validate_scope(scope_path)
    result.errors.extend(scope_result.errors)
    result.warnings.extend(scope_result.warnings)

    authorization_result = check_scope_authorization(scope_result.scope_data, phase)
    result.errors.extend(authorization_result.errors)

    # 2b. Scope target enforcement
    research_primary = bool(
        args.target
        and isinstance(scope_result.scope_data, dict)
        and is_research_host(scope_result.scope_data, args.target)
    )
    target_result = check_scope_targets(
        scope_path,
        args.command,
        args.target,
        allow_research_primary=research_primary,
    )
    result.errors.extend(target_result.errors)
    result.warnings.extend(target_result.warnings)
    if research_primary:
        if phase is not Phase.VULN_RESEARCH:
            result.add_error(
                "research_hosts may be explicit execution targets only during VULN_RESEARCH"
            )
        else:
            result.add_info(
                f"authorized research endpoint: {normalize_target(args.target or '')} "
                "(not an assessment target)"
            )

    # 2c. Destructive-pattern hard block
    destructive_result = check_destructive_patterns(args.command)
    result.errors.extend(destructive_result.errors)

    # 2c2. HTTP proof flags (review): `-i`/`-sv` so receipts are decisive
    proof_result = check_http_proof_flags(args.command)
    result.warnings.extend(proof_result.warnings)
    result.infos.extend(proof_result.infos)

    artifact_result = check_local_artifact_paths(args.command)
    result.infos.extend(artifact_result.infos)

    # 3. Session identity gate
    session_id = state.resolve_session_id(eng_dir, args.session_id)
    if not session_id:
        result.add_error(
            "session_id is required for the skill receipt gate — pass a session_id "
            "(or start one via violin_status) so the active PTT task's skill binding "
            "can be validated."
        )

    # 4. PTT active task
    ptt_path = eng_dir / "state" / "ptt.md"
    ptt_validation = ptt.validate_ptt(ptt.parse_ptt(ptt_path))
    result.errors.extend(ptt_validation.errors)
    result.warnings.extend(ptt_validation.warnings)
    active_task_hyp_id = None
    if ptt_validation.active_task:
        result.infos.append(f"active PTT task: {ptt_validation.active_task}")
        active_task = ptt.find_active_task(ptt_validation.tasks)
        if active_task and not ptt.task_matches_phase(active_task, phase):
            task_phase_display = active_task.phase or "RECON (unspecified '## Phase:' header)"
            result.add_error(
                f"active PTT task {active_task.id} phase is '{task_phase_display}' (heading-derived from '## Phase:' section in state/ptt.md); "
                f"requested phase is '{phase.value}'. Next action: use violin_record_ptt to start a different task already under that phase, "
                "or create one with a new id, title, and phase before executing this command."
            )
        if active_task and active_task.note:
            hyp_match = re.search(r"\bH-\d+\b", active_task.note, re.IGNORECASE)
            if hyp_match:
                active_task_hyp_id = hyp_match.group(0).upper()
        if active_task and session_id:
            binding_result = check_skill_binding(eng_dir, active_task.id, session_id, phase)
            result.errors.extend(binding_result.errors)
            result.warnings.extend(binding_result.warnings)
            result.infos.extend(binding_result.infos)

    semantic_lock = state.semantic_lock(eng_dir)
    if semantic_lock:
        result.add_error(
            "semantic anti-stuck lock: five evidence-poor reviews require a recorded research "
            "attempt plus a meaningful next_technique pivot before target execution. "
            "Unlock by calling violin_record_hypothesis (or the batch review tool) with "
            "research_attempted='true' and a next_technique that differs from the current one, "
            "or by completing an evidence-backed review batch (evidence_paths pointing at saved "
            "output). A new technique OR fresh evidence releases the lock."
        )

    # 5. History staleness (duplicate detection)
    pending = state.get_pending_sync(str(eng_dir)) or {}
    pending_commands = {str(item.get("command") or "") for item in pending.get("commands") or []}
    h_errors, h_warnings, h_infos = history_mod.check_history_staleness(
        eng_dir, args.command, allow_pending_repeat=args.command in pending_commands
    )
    result.errors.extend(h_errors)
    result.warnings.extend(h_warnings)
    result.infos.extend(h_infos)

    # 6. Hypothesis freshness
    hyp_result = check_hypothesis_freshness(
        eng_dir,
        phase,
        args.command,
        args.target,
        hypothesis_id=args.hypothesis_id or active_task_hyp_id,
        match_command_target=not research_primary,
    )
    result.errors.extend(hyp_result.errors)
    result.warnings.extend(hyp_result.warnings)
    result.infos.extend(hyp_result.infos)

    # 7-8. Target execution accounting.
    if args.account_sync:
        sync_pending = state.get_pending_sync(str(eng_dir))
        if sync_pending:
            credit = state.sync_credit_remaining(str(eng_dir), phase.value)
            last_command = (sync_pending.get("commands") or [{}])[-1].get(
                "command", sync_pending.get("command", "prior command")
            )
            if credit == 0:
                result.add_error(
                    f"prior command's artifacts not synced: {last_command} "
                    f"(phase: {sync_pending.get('phase')}). Next: review the batch evidence and call "
                    "violin_review_batch with the active PTT task and a truthful note"
                )
            else:
                result.add_info(
                    f"bounded batch in progress after: {last_command} "
                    f"(phase: {sync_pending.get('phase')}); {credit} credit(s) remain"
                )

        credit = state.sync_credit_remaining(str(eng_dir), phase.value)
        credit_limit = int(
            (sync_pending or {}).get("credit_limit") or state.sync_credit_limit(phase.value)
        )
        result.infos.append(f"sync credit remaining: {credit}/{credit_limit}")
        if credit == 0:
            result.add_error(
                "sync-credit window exhausted; review the saved batch evidence, then call "
                "violin_review_batch (refreshes sync credit)"
            )
    else:
        result.add_info("local analysis is recorded without target sync-credit accounting")

    # 9. Heartbeat gate
    if (
        args.account_sync
        and not suppresses_heartbeat(phase)
        and state.has_heartbeat_pending(str(eng_dir))
    ):
        reason = state.get_heartbeat_reason(str(eng_dir))
        detail = f": {reason}" if reason else ""
        result.add_error(
            f"heartbeat pending{detail} — review engagement state, then run violin_heartbeat_done. "
            "If this run has executed many commands (large context), compact/summarize your "
            "conversation now to stay under the provider prompt-token limit."
        )

    return result


__all__ = [
    "CheckCommandArgs",
    "CheckResult",
    "GuardResult",
    "HypothesisResult",
    "Phase",
    "ScopeResult",
    "_RECORD_AS_YOU_GO_GRACE",
    "accepted_action_aliases",
    "check_command",
    "check_cross_engagement_paths",
    "check_destructive_patterns",
    "check_http_proof_flags",
    "check_hypothesis_freshness",
    "check_local_artifact_paths",
    "check_scope_authorization",
    "check_skill_binding",
    "map_scope_actions",
    "validate_scope",
]
