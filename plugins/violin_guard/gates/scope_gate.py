"""Scope YAML validation and rules of engagement authorization sub-guard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..core.phases import Phase
from ..core.results import GuardResult


@dataclass
class ScopeResult(GuardResult):
    scope_data: dict[str, Any] | None = None

    def print(self) -> None:
        for error in self.errors:
            print(f"BLOCK: {error}")
        for warning in self.warnings:
            print(f"REVIEW: {warning}")
        for info in self.infos:
            print(f"OK: {info}")


def load_scope(scope_path: Path) -> dict[str, Any]:
    """Read a scope mapping or raise a user-facing validation error."""
    if not scope_path.exists():
        raise ValueError(f"scope file not found: {scope_path}")
    try:
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"scope.yaml parse error: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("scope.yaml root must be a mapping")
    return data


def validate_scope(scope_path: Path) -> ScopeResult:
    """Validate scope.yaml structure and required fields."""
    result = ScopeResult()
    try:
        data = load_scope(scope_path)
    except ValueError as exc:
        result.add_error(str(exc))
        return result

    # Required sections
    for section in ("targets", "rules_of_engagement", "engagement"):
        if section not in data:
            result.add_error(f"scope.yaml missing required section: {section}")

    # A real scope must name the approving party and be explicitly confirmed.
    parties = data.get("authorized_parties")
    if not isinstance(parties, list) or not any(str(item).strip() for item in parties):
        result.add_error("scope.authorized_parties must be a non-empty list")
    authorisation = data.get("authorisation")
    if not isinstance(authorisation, dict) or authorisation.get("confirmed") is not True:
        result.add_error("scope.authorisation.confirmed must be true before target execution")

    # A scope may identify targets by IP, CIDR, domain, hostname, URL, or role.
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        result.add_error("scope.targets must be a mapping")
    else:
        target_fields = ("ip_addresses", "cidrs", "domains", "hostnames", "urls", "in_scope_urls")
        has_list_target = any(
            isinstance(targets.get(field), list)
            and any(str(item).strip() for item in targets.get(field, []))
            for field in target_fields
        )
        roles = targets.get("roles")
        has_role_target = isinstance(roles, dict) and any(
            (isinstance(value, list) and any(str(item).strip() for item in value))
            or (isinstance(value, str) and value.strip())
            for value in roles.values()
        )
        if not has_list_target and not has_role_target:
            result.add_error(
                "scope.targets must contain at least one IP, CIDR, domain, hostname, URL, or role"
            )

    assessment_hosts = data.get("assessment_hosts", {}) or {}
    if not isinstance(assessment_hosts, dict):
        result.add_error("scope.assessment_hosts must be a mapping when present")
    else:
        callback_hosts = assessment_hosts.get("callback_hosts", []) or []
        if not isinstance(callback_hosts, list) or any(
            not isinstance(item, str) or not item.strip() for item in callback_hosts
        ):
            result.add_error("scope.assessment_hosts.callback_hosts must be a list of hosts/IPs")

    # rules_of_engagement
    roe = data.get("rules_of_engagement", {})
    allowed_actions = roe.get("allowed_actions") if isinstance(roe, dict) else None
    if not isinstance(allowed_actions, list) or not any(
        str(item).strip() for item in allowed_actions
    ):
        result.add_error("scope.rules_of_engagement.allowed_actions must be a non-empty list")

    # engagement.date
    engagement = data.get("engagement", {})
    if "date" not in engagement:
        result.add_warning("scope.engagement.date missing (will be set on init)")

    result.scope_data = data
    return result


_PHASE_ACTIONS = {
    Phase.SCOPING: frozenset({"scope", "scoping"}),
    Phase.RECON: frozenset(
        {
            "recon",
            "discovery",
            "host port discovery",
            "host-port-discovery",
            "banner grabbing",
            "banner-grabbing",
            "version detection",
            "version-detection",
            "scanning",
            "enumeration",
        }
    ),
    Phase.VULN_RESEARCH: frozenset(
        {
            "vulnerability research",
            "vulnerability-research",
            "vuln-research",
            "research",
            "cve-research",
            "exploitdb",
        }
    ),
    Phase.EXPLOITATION: frozenset(
        {
            "exploitation",
            "exploit validation",
            "exploit-validation",
            "poc",
            "poc validation",
            "poc-validation",
        }
    ),
    Phase.POST_EXPLOITATION: frozenset({"post-exploitation", "post exploitation"}),
    Phase.PRIVESC: frozenset({"privilege escalation", "privilege-escalation", "privesc"}),
    Phase.FLAGS: frozenset({"flags", "flag capture", "flag-capture"}),
    Phase.REPORTING: frozenset({"report", "reporting"}),
    Phase.RETROSPECTIVE: frozenset({"retrospective"}),
}


def _normalize_action(value: object) -> str:
    return " ".join(
        str(value).strip().lower().replace("_", " ").replace("/", " ").replace("-", " ").split()
    )


def _action_key(value: object) -> str:
    """Normalize one exact action alias while allowing trailing qualifiers."""
    raw = str(value).strip()
    while re.search(r"\s*\([^()]*\)\s*$", raw):
        raw = re.sub(r"\s*\([^()]*\)\s*$", "", raw).strip()
    return _normalize_action(raw)


_ACTION_PHASES = {
    _action_key(alias): phase for phase, aliases in _PHASE_ACTIONS.items() for alias in aliases
}


def accepted_action_aliases(phase: Phase) -> list[str]:
    """Return the exact documented spellings accepted for one phase."""
    return sorted(_PHASE_ACTIONS[phase])


def map_scope_actions(items: Any) -> tuple[dict[str, str], list[str]]:
    """Map exact scope actions to phases and retain unrecognized entries."""
    recognized: dict[str, str] = {}
    unknown: list[str] = []
    for item in items if isinstance(items, list) else []:
        mapped = _ACTION_PHASES.get(_action_key(item))
        if mapped is None:
            unknown.append(str(item))
        else:
            recognized[str(item)] = mapped.value
    return recognized, unknown


def _is_action_permitted(allowed_items: Any, phase_actions: frozenset[str]) -> bool:
    accepted = {_action_key(action) for action in phase_actions}
    return any(_action_key(item) in accepted for item in allowed_items)


def check_scope_authorization(scope: dict[str, Any] | None, phase: Phase) -> ScopeResult:
    """Ensure the approved rules of engagement allow the requested phase."""
    result = ScopeResult()
    if not isinstance(scope, dict):
        return result
    roe = scope.get("rules_of_engagement") or {}
    raw_allowed = roe.get("allowed_actions", []) or []
    forbidden = {_action_key(item) for item in roe.get("forbidden_actions", []) or []}
    actions = _PHASE_ACTIONS[phase]
    accepted = {_action_key(action) for action in actions}
    if forbidden & accepted:
        result.add_error(
            f"phase {phase.value} conflicts with scope.rules_of_engagement.forbidden_actions"
        )
    if not _is_action_permitted(raw_allowed, actions):
        allowed_options = accepted_action_aliases(phase)
        formatted_options = ", ".join(f"'{act}'" for act in allowed_options)
        current_str = ", ".join(f"'{item}'" for item in raw_allowed) or "none"
        mapped, unknown = map_scope_actions(raw_allowed)
        mapped_str = ", ".join(f"'{key}' -> {value}" for key, value in mapped.items()) or "none"
        unknown_str = ", ".join(f"'{item}'" for item in unknown) or "none"
        result.add_error(
            f"phase {phase.value} is not permitted by scope.rules_of_engagement.allowed_actions "
            f"(current allowed_actions: [{current_str}]). "
            f"Recognized mappings: [{mapped_str}]. Unrecognized entries: [{unknown_str}]. "
            f"Select and add one of the following valid action strings for {phase.value} to "
            f"rules_of_engagement.allowed_actions in scope/scope.yaml (one of: [{formatted_options}])"
        )
    return result


__all__ = [
    "ScopeResult",
    "accepted_action_aliases",
    "check_scope_authorization",
    "load_scope",
    "map_scope_actions",
    "validate_scope",
]
