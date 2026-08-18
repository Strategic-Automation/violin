"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point and domain subpackage exports.

Architecture & Maintenance Notes:
- Subpackage Structure:
  * `core/`: Pure domain models, Pydantic schemas, state machines, and AST parsing.
  * `gates/`: Security policy engines and preflight validation.
  * `engine/`: Process execution runtime and release verification.
  * `handlers/`: Hermes tool endpoints and request adapters.
  * `hooks.py` & `registry.py`: Lifecycle hooks and plugin discovery registration.
- Extension Rule: Any future export addition must go in its respective subpackage
  (e.g., `core/` for models/state, `gates/` for policies) first.
"""

from __future__ import annotations

from . import core, engine, gates, handlers, hooks, registry
from .core import (
    bash_ast,
    bootstrap,
    findings,
    history,
    hypotheses,
    phases,
    ptt,
    receipt_integrity,
    results,
    runtime_backend,
    schemas,
    skill_policy,
    skill_receipts,
    state,
    targets,
)
from .engine import (
    execution,
    release,
)
from .gates import (
    code_execution_audit,
    command,
    hypothesis_gate,
    scope_gate,
    terminal_policy,
)
from .hooks import (
    _on_session_finalize_hook,
    _on_session_reset_hook,
    _post_tool_call_hook,
    _pre_llm_call_hook,
    _pre_tool_call_hook,
)
from .registry import (
    REGISTERED_TOOLS,
    TOOL_DEFINITIONS,
    ToolDefinition,
    register,
)

__all__ = [
    "REGISTERED_TOOLS",
    "TOOL_DEFINITIONS",
    "ToolDefinition",
    "_on_session_finalize_hook",
    "_on_session_reset_hook",
    "_post_tool_call_hook",
    "_pre_llm_call_hook",
    "_pre_tool_call_hook",
    "bash_ast",
    "bootstrap",
    "code_execution_audit",
    "command",
    "core",
    "engine",
    "execution",
    "findings",
    "gates",
    "handlers",
    "history",
    "hooks",
    "hypotheses",
    "hypothesis_gate",
    "phases",
    "ptt",
    "receipt_integrity",
    "register",
    "registry",
    "release",
    "results",
    "runtime_backend",
    "schemas",
    "scope_gate",
    "skill_policy",
    "skill_receipts",
    "state",
    "targets",
    "terminal_policy",
]
