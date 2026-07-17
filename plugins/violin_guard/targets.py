"""Target extraction, scope enforcement, and target resolution for guarded commands.

This module owns the networking-aware parsing boundary.  It deliberately uses
only Python's standard library: ``shlex`` for commands, ``urllib.parse`` for
URL authorities, and ``ipaddress`` for IP/CIDR validation.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

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
}


@dataclass
class TargetCheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _TargetPolicy:
    allowed: set[str]
    excluded: set[str]
    allowed_networks: list[Network]
    excluded_networks: list[Network]
    research_hosts: set[str]
    callback_hosts: set[str]

    @property
    def known_hosts(self) -> set[str]:
        return self.allowed | self.excluded | self.research_hosts | self.callback_hosts

    def is_excluded(self, candidate: str) -> bool:
        return _matches_host(candidate, self.excluded) or _matches_network(
            candidate, self.excluded_networks
        )

    def is_assessment_target(self, candidate: str) -> bool:
        return _matches_host(candidate, self.allowed) or _matches_network(
            candidate, self.allowed_networks
        )

    def check_primary(self, candidate: str, result: TargetCheckResult) -> None:
        if self.is_excluded(candidate):
            result.errors.append(f"excluded target {candidate} must not be touched")
        elif self.is_assessment_target(candidate):
            return
        elif _is_ip_network(candidate):
            result.errors.append(
                f"out-of-scope target {candidate} (not present in scope.yaml targets)"
            )
        else:
            result.warnings.append(
                f"primary target {candidate} is not present in scope.yaml targets; "
                "verify authorization"
            )

    def check_secondary(self, candidate: str, result: TargetCheckResult) -> None:
        if self.is_excluded(candidate):
            result.errors.append(f"excluded target {candidate} must not be touched")
        elif self.is_assessment_target(candidate) or candidate in (
            self.callback_hosts | self.research_hosts
        ):
            return
        elif _is_ip_network(candidate):
            result.errors.append(f"out-of-scope target {candidate} (not present in scope.yaml)")
        else:
            result.warnings.append(
                f"host {candidate} is not present in scope.yaml; verify authorization"
            )


def extract_target_candidates(command: str) -> list[str]:
    """Return ordered, unique network targets found in a shell command."""

    return list(dict.fromkeys(_target_candidates(command)))


def _target_candidates(command: str) -> list[str]:
    """Return network targets parsed from a shell command."""

    candidates: list[str] = []
    skip_path_value = False
    for token in _command_tokens(command):
        if skip_path_value:
            skip_path_value = False
            continue
        if token in _PATH_VALUE_FLAGS:
            skip_path_value = True
            continue
        if token in _REDIRECTION_OPERATORS or _is_path_option(token):
            continue

        if token.rstrip(";, ").endswith("()"):
            continue
        candidate = token.strip("'\"(),;")
        if (
            _looks_like_local_path(candidate)
            and not _is_network_path(candidate)
            and ("/" not in candidate or candidate.startswith(("/", "./", "../", "~/", "$", "%")))
        ):
            continue
        host = _parse_target_token(candidate)
        if host:
            candidates.append(host)
    return candidates


def normalise_target(value: str) -> str:
    """Return a comparable host, accepting legacy ``host (description)`` values."""

    raw = value.strip()
    raw = re.split(r"\s+\(", raw, maxsplit=1)[0].strip()
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            return parsed.hostname.lower()
    except ValueError:
        pass
    return raw.lower()


def resolve_target(
    scope_data: dict[str, Any],
    role: str | None,
    host_query: str | None,
    field: str = "ip",
) -> str | None:
    """Resolve a single target value from scope data.

    Resolution order:
      1. Explicit role lookup
      2. Host query against in-scope hosts
      3. Fallback to first ip_address, then url/domain/hostname/role value

    Returns the resolved raw string (before field extraction), or None if no
    target is found.
    """
    targets_sec = scope_data.get("targets", {}) or {}
    target_val: str | None = None

    # 1. Resolve by role
    if role:
        roles = targets_sec.get("roles", {}) or {}
        role_val = roles.get(role)
        if isinstance(role_val, list) and role_val:
            target_val = str(role_val[0]).strip()
        elif role_val is not None:
            target_val = str(role_val).strip()

    # 2. Resolve by host query
    if not target_val and host_query:
        allowed_hosts = scope_hosts(scope_data)
        norm_host = normalise_target(host_query)
        if norm_host in allowed_hosts:
            target_val = host_query.strip()

    # 3. Fallback chain: ip_addresses -> urls/in_scope_urls -> domains -> hostnames -> roles
    if not target_val:
        for key in ("ip_addresses", "urls", "in_scope_urls", "domains", "hostnames"):
            items = targets_sec.get(key, [])
            if isinstance(items, list) and items:
                target_val = str(items[0]).strip()
                break

        if not target_val:
            roles = targets_sec.get("roles", {}) or {}
            if roles:
                first_val = next(iter(roles.values()))
                if isinstance(first_val, list) and first_val:
                    target_val = str(first_val[0]).strip()
                elif first_val is not None:
                    target_val = str(first_val).strip()

    if not target_val:
        return None

    # Extract the requested field from a URL
    if "://" in target_val and field in ("ip", "host"):
        try:
            parsed = urlsplit(target_val)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass

    return target_val


def check_scope_targets(
    scope_path: Path, command: str, primary_target: str | None = None
) -> TargetCheckResult:
    """Block excluded or out-of-scope IP/CIDR targets in ``command``."""

    result = TargetCheckResult()
    scope = _read_scope(scope_path)
    if scope is None:
        return result

    policy = _target_policy(scope)
    explicit = normalise_target(primary_target) if primary_target else ""
    candidates = _target_candidates(command)
    seen: set[str] = set()
    if explicit:
        seen.add(explicit)
        policy.check_primary(explicit, result)
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        policy.check_secondary(candidate, result)
    return result


def _target_policy(scope: dict[str, Any]) -> _TargetPolicy:
    return _TargetPolicy(
        allowed=scope_hosts(scope, "targets"),
        excluded=scope_hosts(scope, "exclusions"),
        allowed_networks=_scope_networks(scope, "targets"),
        excluded_networks=_scope_networks(scope, "exclusions"),
        research_hosts=_research_hosts(scope),
        callback_hosts=_callback_hosts(scope),
    )


def _command_tokens(command: str) -> list[str]:
    """Tokenize a command and one quoted nested-command level."""

    tokens = _split_shell_words(command)
    return tokens + [
        nested for token in tokens if " " in token for nested in _split_shell_words(token)
    ]


def _split_shell_words(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return value.split()


def _parse_target_token(token: str) -> str | None:
    dev_host = _dev_network_host(token)
    if dev_host:
        return dev_host

    raw = token.strip().rstrip("/.,;)")
    if not raw:
        return None
    unbracketed = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        if "/" in unbracketed:
            return str(ipaddress.ip_network(unbracketed, strict=False)).lower()
        return str(ipaddress.ip_address(unbracketed)).lower()
    except ValueError:
        pass

    try:
        parsed = urlsplit(raw if raw.startswith("//") or "://" in raw else f"//{raw}")
    except ValueError:
        return None
    return _valid_hostname(parsed.hostname) if parsed.hostname else None


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
    if not host or len(host) > 253 or len(labels) < 2:
        return None
    if any(not label or len(label) > 63 for label in labels):
        return None
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return None
    if any(
        not all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        return None
    return host


def _is_path_option(token: str) -> bool:
    return any(token.startswith(f"{flag}=") for flag in _PATH_VALUE_FLAGS)


def _is_network_path(token: str) -> bool:
    return token.startswith(_DEV_NETWORK_PREFIXES) or token.startswith("//") or "://" in token


def _looks_like_local_path(token: str) -> bool:
    normalized = token.replace("\\", "/")
    return (
        normalized.startswith(("/", "./", "../", "~/", "$", "%"))
        or "/" in normalized
        or any(normalized.lower().endswith(suffix) for suffix in _COMMON_FILE_SUFFIXES)
    )


def _read_scope(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def scope_hosts(scope: dict[str, Any], section: str = "targets") -> set[str]:
    """Return canonical hosts from one scope section."""

    values = scope.get(section, {}) or {}
    if section == "exclusions":
        return {normalise_target(value) for value in _values(values)}
    keys = ("ip_addresses", "in_scope_urls", "urls", "domains", "hostnames", "roles")
    return {normalise_target(value) for key in keys for value in _values(values.get(key, []))}


def _research_hosts(scope: dict[str, Any]) -> set[str]:
    """Return explicit public reference hosts, never assessment targets."""
    return {normalise_target(value) for value in _values(scope.get("research_hosts", []))}


def _callback_hosts(scope: dict[str, Any]) -> set[str]:
    """Return operator-approved local callback/listener infrastructure."""

    assessment_hosts = scope.get("assessment_hosts", {}) or {}
    if not isinstance(assessment_hosts, dict):
        return set()
    return {
        normalise_target(value) for value in _values(assessment_hosts.get("callback_hosts", []))
    }


def _scope_networks(scope: dict[str, Any], section: str) -> list[Network]:
    values = scope.get(section, {}) or {}
    networks: list[Network] = []
    for key in ("ip_addresses", "cidrs"):
        for value in _values(values.get(key, [])):
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
    return networks


def _values(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _values(nested)
    elif value is not None:
        yield str(value)


def _matches_network(candidate: str, networks: list[Network]) -> bool:
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return any(
        network.version == allowed.version and network.subnet_of(allowed) for allowed in networks
    )


def _matches_host(candidate: str, allowed: set[str]) -> bool:
    """Match an exact hostname or a scope wildcard such as ``*.example.test``."""
    if candidate in allowed:
        return True
    return any(
        pattern.startswith("*.") and candidate.endswith(pattern[1:]) and candidate != pattern[2:]
        for pattern in allowed
    )


def _is_ip_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


__all__ = [
    "TargetCheckResult",
    "extract_target_candidates",
    "normalise_target",
    "resolve_target",
    "check_scope_targets",
    "scope_hosts",
]
