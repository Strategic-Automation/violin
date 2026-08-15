"""Target extraction, scope enforcement, and target resolution for guarded commands.

This module owns the networking-aware parsing boundary, using AST-based shell tokenization
via bashlex, netaddr for IP/CIDR set arithmetic, and yarl for RFC 3986 URL parsing.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import netaddr
from yarl import URL

from .bash_ast import extract_all_command_words

_PATH_VALUE_FLAGS = {
    "-o",
    "-oA",
    "-oG",
    "-oN",
    "-oX",
    "--log-file",
    "--outfile",
    "--output",
    "--output-dir",
}
_REDIRECTION_OPERATORS = {">", ">>", "2>", "2>>", "&>"}
_DEV_NETWORK_PREFIXES = ("/dev/tcp/", "/dev/udp/")
_COMMON_FILE_SUFFIXES = {
    ".html",
    ".htm",
    ".js",
    ".json",
    ".py",
    ".php",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
    ".xml",
    ".zip",
    ".vsix",
    ".exe",
    ".dll",
    ".token",
    ".pem",
    ".key",
}
_NON_TARGET_DOTTED_TOKENS = frozenset(
    {
        "urllib.request",
        "urllib.parse",
        "urllib.error",
        "http.client",
        "http.server",
        "json.decoder",
        "json.encoder",
        "json.tool",
        "xml.etree",
        "unittest.mock",
        "importlib.util",
        "asyncio.runner",
        "wsgiref.simple_server",
        "jwt.io",
        "example.com",
        "example.org",
        "example.net",
        "schema.org",
        "w3.org",
    }
)
_LOCAL_HOSTS = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}


@dataclass
class TargetCheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _TargetPolicy:
    allowed: set[str]
    excluded: set[str]
    allowed_ip_set: netaddr.IPSet
    excluded_ip_set: netaddr.IPSet
    research_hosts: set[str]
    callback_hosts: set[str]
    excluded_urls: set[str]
    excluded_paths: set[str]

    def check_command_payload(self, command: str, result: TargetCheckResult) -> None:
        if not self.excluded_urls and not self.excluded_paths:
            return
        for token in _command_tokens(command):
            candidate = token.strip("'\"(),;")
            if not candidate:
                continue

            for url in self.excluded_urls:
                if url and url in candidate:
                    result.errors.append(
                        f"strict block: command payload contains excluded URL '{url}'"
                    )
                    break

            for path in self.excluded_paths:
                if not path:
                    continue
                if candidate == path:
                    result.errors.append(
                        f"strict block: command payload contains excluded path '{path}'"
                    )
                    break
                if "://" in candidate or candidate.startswith("/"):
                    with contextlib.suppress(Exception):
                        cand_url = URL(
                            candidate if "://" in candidate else f"http://dummy.local{candidate}"
                        )
                        cpath = cand_url.path
                        norm_ex = path.rstrip("/")
                        if cpath in (path, norm_ex) or cpath.startswith(norm_ex + "/"):
                            result.errors.append(
                                f"strict block: command payload contains excluded path '{path}'"
                            )
                            break

    def is_excluded(self, candidate: str) -> bool:
        return _matches_host(candidate, self.excluded) or _matches_ip_set(
            candidate, self.excluded_ip_set
        )

    def is_assessment_target(self, candidate: str) -> bool:
        return _matches_host(candidate, self.allowed) or _matches_ip_set(
            candidate, self.allowed_ip_set
        )

    def is_secondary_only(self, candidate: str) -> bool:
        return _matches_host(candidate, self.callback_hosts | self.research_hosts | _LOCAL_HOSTS)

    def check_primary(
        self,
        candidate: str,
        result: TargetCheckResult,
        *,
        allow_research: bool = False,
    ) -> None:
        if self.is_excluded(candidate):
            result.errors.append(f"excluded target {candidate} must not be touched")
        elif allow_research and _matches_host(candidate, self.research_hosts):
            return
        elif self.is_secondary_only(candidate):
            result.errors.append(
                f"secondary-only endpoint {candidate} must not be used as a primary target"
            )
        elif self.is_assessment_target(candidate):
            return
        elif _is_ip_network(candidate):
            result.errors.append(
                f"out-of-scope target {candidate} (not present in scope.yaml targets)"
            )
        else:
            result.warnings.append(
                f"primary target {candidate} is not present in scope.yaml targets; verify authorization"
            )

    def check_secondary(self, candidate: str, result: TargetCheckResult) -> None:
        if self.is_excluded(candidate):
            result.errors.append(f"excluded target {candidate} must not be touched")
        elif self.is_assessment_target(candidate) or self.is_secondary_only(candidate):
            return
        elif _is_ip_network(candidate):
            result.errors.append(f"out-of-scope target {candidate} (not present in scope.yaml)")
        else:
            result.warnings.append(
                f"host {candidate} is not present in scope.yaml; verify authorization"
            )


def extract_target_candidates(command: str) -> list[str]:
    """Return ordered, unique network targets found in a shell command."""
    candidates: list[str] = []
    skip_path_value = False
    skip_next_token = False
    for token in _command_tokens(command):
        if skip_path_value:
            skip_path_value = False
            continue
        if skip_next_token:
            skip_next_token = False
            continue
        if token in _PATH_VALUE_FLAGS:
            skip_path_value = True
            continue
        if token == "-m" or token.startswith("-m="):
            if token == "-m":
                skip_next_token = True
            continue
        if token in _REDIRECTION_OPERATORS or any(
            token.startswith(f"{flag}=") for flag in _PATH_VALUE_FLAGS
        ):
            continue

        if token.rstrip(";, ").endswith("()"):
            continue
        candidate = token.strip("'\"(),;")
        if candidate.lower() in _NON_TARGET_DOTTED_TOKENS:
            continue
        if _looks_like_local_path(candidate) and not (
            candidate.startswith(_DEV_NETWORK_PREFIXES)
            or candidate.startswith("//")
            or "://" in candidate
        ):
            continue
        parsed = _parse_target_token(candidate)
        if parsed:
            candidates.append(parsed)
    return list(dict.fromkeys(candidates))


def normalise_target(value: str) -> str:
    """Return a canonical hostname, taking advantage of yarl for RFC 3986 URL parsing."""
    raw = re.split(r"\s+\(", value.strip(), maxsplit=1)[0].strip()
    with contextlib.suppress(Exception):
        url = URL(raw if "://" in raw else f"//{raw}")
        if url.host:
            return url.host.lower()
    return raw.lower()


def resolve_target(
    scope_data: dict[str, Any],
    role: str | None,
    host_query: str | None,
    field: str = "ip",
) -> str | None:
    """Resolve a single target value from scope data."""
    targets_sec = scope_data.get("targets", {}) or {}
    role = str(role or "").strip()
    host_query = str(host_query or "").strip()
    if role and host_query:
        raise ValueError("provide exactly one of role or host, not both")

    target_val: str | None = None
    if role:
        roles = targets_sec.get("roles", {}) or {}
        if role not in roles:
            raise ValueError(f"target role {role!r} is not defined in scope.yaml")
        values = [value.strip() for value in _values(roles[role]) if value.strip()]
        unique = list(dict.fromkeys(values))
        if len(unique) != 1:
            raise ValueError(f"target role {role!r} is ambiguous; expected exactly one value")
        target_val = unique[0]
    elif host_query:
        if normalise_target(host_query) not in scope_hosts(scope_data):
            raise ValueError(f"target host {host_query!r} is not present in scope.yaml")
        target_val = host_query
    else:
        raw_values = [
            value.strip()
            for key in ("ip_addresses", "urls", "in_scope_urls", "domains", "hostnames", "roles")
            for value in _values(targets_sec.get(key, []))
            if value.strip()
        ]
        by_host: dict[str, str] = {}
        for value in raw_values:
            by_host.setdefault(normalise_target(value), value)
        if len(by_host) > 1:
            raise ValueError("multiple targets are in scope; select one with host or role")
        target_val = next(iter(by_host.values()), None)

    if not target_val:
        return None

    if "://" in target_val and field in ("ip", "host"):
        with contextlib.suppress(Exception):
            url = URL(target_val)
            if url.host:
                return url.host

    return target_val


def _research_hosts(scope: dict[str, Any]) -> set[str]:
    """Return explicit public reference hosts, never assessment targets."""
    return {normalise_target(v) for v in _values(scope.get("research_hosts", []))}


def is_research_host(scope: dict[str, Any], candidate: str | None) -> bool:
    """Return whether ``candidate`` is an explicitly authorized research host."""
    normalized = normalise_target(candidate) if candidate else ""
    return bool(normalized and _matches_host(normalized, _research_hosts(scope)))


def _callback_hosts(scope: dict[str, Any]) -> set[str]:
    """Return operator-approved local callback/listener infrastructure."""
    assessment_hosts = scope.get("assessment_hosts", {}) or {}
    if not isinstance(assessment_hosts, dict):
        return set()
    return {normalise_target(v) for v in _values(assessment_hosts.get("callback_hosts", []))}


def check_scope_targets(
    scope_path: Path,
    command: str,
    primary_target: str | None = None,
    *,
    allow_research_primary: bool = False,
) -> TargetCheckResult:
    """Block excluded or out-of-scope IP/CIDR targets in ``command``."""
    result = TargetCheckResult()
    scope = _read_scope(scope_path)
    if scope is None:
        return result

    exclusions = scope.get("exclusions", {}) or {}
    policy = _TargetPolicy(
        allowed=scope_hosts(scope, "targets"),
        excluded=scope_hosts(scope, "exclusions"),
        allowed_ip_set=_scope_ip_set(scope, "targets"),
        excluded_ip_set=_scope_ip_set(scope, "exclusions"),
        research_hosts=_research_hosts(scope),
        callback_hosts=_callback_hosts(scope),
        excluded_urls={v for v in _values(exclusions.get("urls", []))},
        excluded_paths={v for v in _values(exclusions.get("paths", []))},
    )

    explicit = normalise_target(primary_target) if primary_target else ""
    candidates = extract_target_candidates(command)
    seen: set[str] = set()
    if explicit:
        seen.add(explicit)
        policy.check_primary(explicit, result, allow_research=allow_research_primary)
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            policy.check_secondary(candidate, result)

    policy.check_command_payload(command, result)
    return result


def _command_tokens(command: str) -> list[str]:
    """Tokenize a command and nested subcommands using bashlex AST."""
    return extract_all_command_words(command)


def _parse_target_token(token: str) -> str | None:
    dev_host = _dev_network_host(token)
    if dev_host:
        return dev_host

    raw = token.strip().rstrip("/.,;)")
    if not raw:
        return None
    unbracketed = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw

    with contextlib.suppress(ValueError):
        if "/" in unbracketed:
            return str(ipaddress.ip_network(unbracketed, strict=False)).lower()
        return str(ipaddress.ip_address(unbracketed)).lower()

    with contextlib.suppress(Exception):
        url = URL(raw if raw.startswith("//") or "://" in raw else f"//{raw}")
        if url.host:
            with contextlib.suppress(ValueError):
                return str(ipaddress.ip_address(url.host)).lower()
            return _valid_hostname(url.host)

    return None


def _dev_network_host(token: str) -> str | None:
    normalized = token.strip("'\"(),;")
    prefix = next((item for item in _DEV_NETWORK_PREFIXES if normalized.startswith(item)), None)
    if prefix is None:
        return None
    host, separator, port = normalized.removeprefix(prefix).partition("/")
    if not separator or "/" in port or not port.isdigit() or not 0 < int(port) < 65536:
        return None
    return _parse_target_token(host)


def _valid_hostname(value: str) -> str | None:
    host = value.strip().rstrip(".").lower()
    labels = host.split(".")
    if (
        not host
        or len(host) > 253
        or len(labels) < 2
        or all(label.isdigit() for label in labels)
        or labels[-1].isdigit()
    ):
        return None
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        return None
    return host


def _looks_like_local_path(token: str) -> bool:
    normalized = token.replace("\\", "/")
    if normalized.startswith(("/", "./", "../", "~/", "$", "%")):
        return True
    if any(normalized.lower().endswith(suffix) for suffix in _COMMON_FILE_SUFFIXES):
        return True
    if "/" in normalized:
        first_part = normalized.split("/", 1)[0]
        return not _valid_hostname(first_part)
    return False


def _read_scope(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def scope_hosts(scope: dict[str, Any], section: str = "targets") -> set[str]:
    """Return canonical hosts from one scope section."""
    values = scope.get(section, {}) or {}
    if section == "exclusions":
        keys = ("ip_addresses", "domains", "hostnames", "roles")
        return {normalise_target(value) for key in keys for value in _values(values.get(key, []))}
    keys = ("ip_addresses", "in_scope_urls", "urls", "domains", "hostnames", "roles")
    return {normalise_target(value) for key in keys for value in _values(values.get(key, []))}


def _scope_ip_set(scope: dict[str, Any], section: str) -> netaddr.IPSet:
    values = scope.get(section, {}) or {}
    ip_set = netaddr.IPSet()
    for key in ("ip_addresses", "cidrs", "ranges"):
        for value in _values(values.get(key, [])):
            with contextlib.suppress(Exception):
                if "-" in value and not value.startswith("-"):
                    parts = value.split("-", 1)
                    ip_set.add(netaddr.IPRange(parts[0].strip(), parts[1].strip()))
                else:
                    ip_set.add(netaddr.IPNetwork(value))
    return ip_set


def _values(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _values(nested)
    elif value is not None:
        yield str(value)


def _matches_ip_set(candidate: str, ip_set: netaddr.IPSet) -> bool:
    if not ip_set:
        return False
    with contextlib.suppress(Exception):
        if "/" in candidate:
            cand_net = netaddr.IPNetwork(candidate)
            return cand_net in ip_set or ip_set.issuperset(cand_net)
        cand_ip = netaddr.IPAddress(candidate)
        return cand_ip in ip_set
    return False


def _matches_host(candidate: str, allowed: set[str]) -> bool:
    """Match an exact hostname or a scope wildcard such as ``*.example.test``."""
    if candidate in allowed:
        return True
    return any(
        pattern.startswith("*.") and candidate.endswith(pattern[1:]) and candidate != pattern[2:]
        for pattern in allowed
    )


def _is_ip_network(value: str) -> bool:
    with contextlib.suppress(Exception):
        netaddr.IPNetwork(value)
        return True
    return False


def resolve_command_targets(
    command: str,
    primary_target: str | None = None,
    scope_data: dict[str, Any] | None = None,
) -> set[str]:
    """Extract and normalise candidate targets from command, primary target, or scope fallback."""
    targets = {normalise_target(t) for t in extract_target_candidates(command)}
    if primary_target:
        targets.add(normalise_target(primary_target))

    if not targets and isinstance(scope_data, dict):
        targets_sec = scope_data.get("targets", {})
        if isinstance(targets_sec, dict):
            for t in targets_sec.get("ip_addresses", []) or []:
                if isinstance(t, str) and t.strip():
                    targets.add(normalise_target(t))

    return targets


__all__ = [
    "TargetCheckResult",
    "check_scope_targets",
    "extract_target_candidates",
    "normalise_target",
    "resolve_command_targets",
    "resolve_target",
    "scope_hosts",
]
