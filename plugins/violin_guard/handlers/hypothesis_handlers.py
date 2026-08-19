"""Hypothesis tracking handlers."""

from __future__ import annotations

from ..core import hypotheses, state
from ..core.targets import scope_hosts
from ..gates.scope_gate import load_scope
from .base import _eng_path, _json, _serialize_errors


def _scope_hosts(eng_dir: str, target: str) -> set[str] | None:
    """Return canonical scope hosts, requiring a valid scope for targeted records."""
    scope_path = _eng_path(eng_dir) / "scope" / "scope.yaml"
    if not scope_path.exists():
        if target.strip():
            raise ValueError("targeted hypotheses require a valid scope/scope.yaml")
        return None
    return scope_hosts(load_scope(scope_path))


@_serialize_errors
def handle_record_hypothesis(args, **kwargs):
    eng_dir = args["eng_dir"]
    fields = {k: v for k, v in args.items() if k != "eng_dir"}
    in_scope = _scope_hosts(eng_dir, str(fields.get("target") or ""))
    with state.workflow_lock(eng_dir):
        requested_id = str(fields.get("id") or "").strip()
        existing = {
            hypothesis.id
            for hypothesis in hypotheses.parse_hypotheses(_eng_path(eng_dir) / "hypotheses.md")
        }
        h = hypotheses.update_hypothesis(
            _eng_path(eng_dir) / "hypotheses.md", in_scope_hosts=in_scope, **fields
        )
        if fields.get("cve_research") or fields.get("exploit_research"):
            state.record_research_attempt(eng_dir, "hypothesis_research", True)
    operation = "updated" if requested_id and h.id in existing else "created"
    return _json("ok", operation=operation, hypothesis=h.to_dict())
