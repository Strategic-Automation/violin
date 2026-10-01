"""Declarative, fail-closed routing policy for Violin skill selection."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches

from ...core.engagement.phases import Phase, normalize_phase
from .skill_catalog import _normalize, skill_spec, validate_catalog


@dataclass(frozen=True)
class RouteDecision:
    """Deterministic skill choice plus every policy-permitted alternative."""

    phase: str
    vulnerability_class: str
    candidate_source: str
    selected: str | None
    allowed: tuple[str, ...]
    mismatch_reasons: tuple[str, ...]


_VULNERABILITY_ROUTES = {
    "default-credentials": "identity-auth",
    "mass-assignment": "api-testing",
    "missing-authentication": "identity-auth",
    "idor-access-control": "identity-auth",
    "jwt-attacks": "identity-auth",
    "workflow-state-abuse": "business-logic",
    "auth": "identity-auth",
    "authn": "identity-auth",
    "authz": "identity-auth",
    "access-control": "identity-auth",
    "auth-bypass": "identity-auth",
    "authentication": "identity-auth",
    "authorization": "identity-auth",
    "broken-access-control": "identity-auth",
    "broken-object-level-authorization": "identity-auth",
    "cors": "misconfig",
    "csrf": "identity-auth",
    "cryptographic-issues": "identity-auth",
    "idor": "identity-auth",
    "jwt": "identity-auth",
    "open-redirect": "identity-auth",
    "redirects-unvalidated": "identity-auth",
    "command-injection": "web-app",
    "cross-site-scripting": "web-app",
    "deserialization": "web-app",
    "input-validation": "web-app",
    "ldap-injection": "web-app",
    "nosql-injection": "web-app",
    "path-traversal": "web-app",
    "prototype-pollution": "web-app",
    "rate-limit": "web-app",
    "rate-limiting": "web-app",
    "sqli": "web-app",
    "sql-injection": "web-app",
    "ssrf": "web-app",
    "server-side-request-forgery": "web-app",
    "ssti": "web-app",
    "xss": "web-app",
    "xpath-injection": "web-app",
    "xxe": "web-app",
    "api-security": "api-testing",
    "graphql": "api-testing",
    "rest-api": "api-testing",
    "websocket": "api-testing",
    "business-logic": "business-logic",
    "business-logic-flaw": "business-logic",
    "logic-flaw": "business-logic",
    "llm-prompt-injection": "llm-security",
    "prompt-injection": "llm-security",
    "json-rpc": "llm-security",
    "mcp": "llm-security",
    "mcp-api-testing": "llm-security",
    "misconfiguration": "misconfig",
    "observability-failures": "misconfig",
    "security-misconfiguration": "misconfig",
    "security-through-obscurity": "misconfig",
    "source-analysis": "audit-context-building",
    "static-analysis": "semgrep",
    "sarif": "sarif-parsing",
    "false-positive": "fp-check",
}
_SOURCE_ROUTES = {
    "api-enumeration": "api-testing",
    "domain": "domain-intel",
    "osint": "osint-investigation",
    "public-records": "osint-investigation",
    "username": "sherlock",
    "identity": "sherlock",
    "repository": "oss-forensics",
    "supply-chain": "oss-forensics",
    "codebase": "audit-context-building",
    "source": "audit-context-building",
    "semgrep": "semgrep",
    "codeql": "codeql",
    "sarif": "sarif-parsing",
}
_PHASE_DEFAULTS = {
    Phase.SCOPING: "pentest",
    Phase.RECON: "pentest",
    Phase.VULN_RESEARCH: "pentest",
    Phase.EXPLOITATION: "pentest",
    Phase.POST_EXPLOITATION: "pentest",
    Phase.PRIVESC: "pentest",
    Phase.FLAGS: "pentest",
    Phase.REPORTING: "pentest",
    Phase.RETROSPECTIVE: "pentest",
}


def _candidate_source_guidance() -> str:
    """Render the public, normalized candidate-source vocabulary and its routes."""

    return ", ".join(f"{source} -> {skill}" for source, skill in sorted(_SOURCE_ROUTES.items()))


def _route_basis(decision: RouteDecision) -> str:
    """Explain the highest-priority input that selected one mandatory skill."""

    if decision.vulnerability_class in _VULNERABILITY_ROUTES:
        return (
            f"vulnerability_class {decision.vulnerability_class!r} "
            "(vulnerability routes take precedence over candidate_source)"
        )
    if decision.candidate_source in _SOURCE_ROUTES:
        return f"candidate_source {decision.candidate_source!r}"
    return f"phase {decision.phase!r} default"


_VULNERABILITY_SUGGESTION_CUTOFF = 0.8
_SUGGESTION_TOKEN_ALIASES = {"authentication": "auth"}


def _suggestion_tokens(value: str) -> list[str]:
    """Split route-like suggestion text on canonical and descriptive separators."""
    return value.replace("/", "-").split("-")


def _vulnerability_class_suggestion(canonical: str) -> str | None:
    """Suggest a canonical class without changing policy.

    Prefer typo completions, aligned alias suffixes, and exact route extensions;
    ambiguous suffixes return no hint before the conservative fuzzy fallback.
    """
    routes = sorted(_VULNERABILITY_ROUTES)
    prefixes = [route for route in routes if len(canonical) >= 6 and route.startswith(canonical)]
    if prefixes:
        return min(prefixes, key=len)

    query_tokens = _suggestion_tokens(canonical)
    query_prefix_tokens = query_tokens[:-1]
    suffix = query_tokens[-1]
    suffix_matches: list[str] = []
    alias_suffix_matches: list[str] = []
    for route in routes:
        route_tokens = _suggestion_tokens(route)
        if len(route_tokens) < 2 or route_tokens[-1] != suffix:
            continue
        route_prefix_tokens = route_tokens[:-1]
        if len(route_prefix_tokens) > len(query_prefix_tokens):
            continue
        pairs = zip(route_prefix_tokens, query_prefix_tokens, strict=False)
        if all(query_token == route_token for route_token, query_token in pairs):
            suffix_matches.append(route)
            continue
        pairs = zip(route_prefix_tokens, query_prefix_tokens, strict=False)
        if all(
            _SUGGESTION_TOKEN_ALIASES.get(query_token, query_token) == route_token
            for route_token, query_token in pairs
        ):
            alias_suffix_matches.append(route)
    if len(alias_suffix_matches) == 1:
        return alias_suffix_matches[0]

    extensions = [route for route in routes if canonical.startswith(f"{route}-")]
    if extensions:
        close_route = get_close_matches(canonical, routes, n=1, cutoff=0.9)
        if close_route:
            return close_route[0]
        return max(extensions, key=len)

    if len(suffix_matches) == 1:
        return suffix_matches[0]

    shared_suffix_routes = [
        route
        for route in routes
        if len(_suggestion_tokens(route)) > 1 and _suggestion_tokens(route)[-1] == suffix
    ]
    if len(shared_suffix_routes) > 1:
        route_prefixes = [
            "-".join(_suggestion_tokens(route)[:-1]) for route in shared_suffix_routes
        ]
        query_prefix = "-".join(query_prefix_tokens)
        route_prefixes = [prefix for prefix in route_prefixes if query_prefix[:1] == prefix[:1]]
        close_prefix = get_close_matches(
            query_prefix,
            route_prefixes,
            n=1,
            cutoff=_VULNERABILITY_SUGGESTION_CUTOFF,
        )
        if not close_prefix:
            return None

    matches = get_close_matches(
        canonical,
        routes,
        n=1,
        cutoff=_VULNERABILITY_SUGGESTION_CUTOFF,
    )
    if matches:
        return matches[0]

    exact_token_matches = [route for route in routes if route in query_tokens]
    if len(exact_token_matches) == 1:
        return exact_token_matches[0]
    return None


def resolve_skill_route(
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> RouteDecision:
    """Resolve one policy route without consulting state or installed skills."""

    catalog_errors = validate_catalog()
    raw_vulnerability = _normalize(vulnerability_class)
    raw_source = _normalize(candidate_source)
    try:
        canonical_phase = normalize_phase(phase)
    except (AttributeError, ValueError):
        return RouteDecision(
            str(phase),
            raw_vulnerability,
            raw_source,
            None,
            (),
            (f"unknown phase: {phase}", *catalog_errors),
        )
    selected = _VULNERABILITY_ROUTES.get(raw_vulnerability)
    if selected is None:
        selected = _SOURCE_ROUTES.get(raw_source)
    if selected is None:
        selected = _PHASE_DEFAULTS[canonical_phase]
    mismatch: list[str] = list(catalog_errors)
    if raw_vulnerability and raw_vulnerability not in _VULNERABILITY_ROUTES:
        valid_classes = ", ".join(sorted(_VULNERABILITY_ROUTES.keys()))
        if skill_spec(raw_vulnerability) is not None:
            mismatch.append(
                f"'{vulnerability_class}' is a skill name, not a vulnerability class. "
                f"Set skill='{raw_vulnerability}'. Set vuln_class to an observed "
                f"class (for example: sqli, ssrf, jwt, or idor); valid classes are: "
                f"{valid_classes}"
            )
        else:
            suggestion = _vulnerability_class_suggestion(raw_vulnerability)
            message = f"unknown vulnerability class: {vulnerability_class!r}"
            if suggestion:
                message += f". Did you mean '{suggestion}'?"
                separator = " "
            else:
                separator = ". "
            mismatch.append(f"{message}{separator}Valid classes are: {valid_classes}")
    if raw_source and raw_source not in _SOURCE_ROUTES:
        mismatch.append(
            f"unknown candidate source: {candidate_source!r}; accepted normalized values and routes: "
            + _candidate_source_guidance()
            + ". If this value names a vulnerability type (for example jwt, idor, xss, or ssrf), "
            "pass it as vuln_class instead of candidate_source."
        )
    allowed = () if mismatch else (selected,)
    return RouteDecision(
        canonical_phase.value, raw_vulnerability, raw_source, selected, allowed, tuple(mismatch)
    )


def routable_context(
    vulnerability_class: str | None = None, candidate_source: str | None = None
) -> tuple[str, str]:
    """Return the part of a recorded context that the router can act on.

    A hypothesis board is free text: its ``candidate_source`` may name a tool, a
    directory, or a phrase with no route. Passing such a value on to
    :func:`validate_skill_selection` adds an "unknown candidate source" mismatch
    and fails an otherwise valid call, so a *derived* hint is filtered to the
    values that map to a route while an explicit caller value stays the caller's
    responsibility.
    """

    vulnerability = _normalize(vulnerability_class)
    source = _normalize(candidate_source)
    return (
        vulnerability if vulnerability in _VULNERABILITY_ROUTES else "",
        source if source in _SOURCE_ROUTES else "",
    )


def validate_skill_selection(
    selected_skill: str,
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> RouteDecision:
    """Resolve and add a fail-closed explanation for an LLM skill mismatch."""

    decision = resolve_skill_route(phase, vulnerability_class, candidate_source)
    selection = _normalize(selected_skill)
    reasons = list(decision.mismatch_reasons)
    if selection == "fp-check" and decision.phase == Phase.RETROSPECTIVE.value and not reasons:
        return RouteDecision(
            decision.phase,
            decision.vulnerability_class,
            decision.candidate_source,
            selection,
            (selection,),
            (),
        )
    if skill_spec(selection) is None:
        reasons.append(f"unknown or unapproved skill: {selected_skill}")
    elif decision.allowed and selection not in decision.allowed:
        reasons.append(
            f"skill {selected_skill!r} is not permitted; expected {decision.selected!r} "
            f"because {_route_basis(decision)}. Set skill={decision.selected!r}."
        )
    return RouteDecision(
        decision.phase,
        decision.vulnerability_class,
        decision.candidate_source,
        decision.selected,
        decision.allowed if not reasons else (),
        tuple(reasons),
    )
