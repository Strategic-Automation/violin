"""Target extraction and scope enforcement for guarded commands.

This module owns the networking-aware parsing boundary.  It deliberately uses
only Python's standard library: ``shlex`` for commands, ``urllib.parse`` for
URL authorities, and ``ipaddress`` for IP/CIDR validation.
"""

from __future__ import annotations

import ipaddress
import mimetypes
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


@dataclass
class TargetCheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def extract_target_candidates(command: str) -> list[str]:
    """Return ordered, unique network targets found in a shell command."""

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
        if _looks_like_local_path(candidate) and not _is_network_path(candidate):
            continue
        host = _parse_target_token(candidate)
        if host:
            candidates.append(host)
    return list(dict.fromkeys(candidates))


def normalise_target(value: str) -> str:
    """Return a comparable host for a URL, host:port, or bare target."""

    raw = value.strip()
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            return parsed.hostname.lower()
    except ValueError:
        pass
    return raw.lower()


def check_scope_targets(scope_path: Path, command: str) -> TargetCheckResult:
    """Block excluded or out-of-scope IP/CIDR targets in ``command``."""

    result = TargetCheckResult()
    scope = _read_scope(scope_path)
    if scope is None:
        return result

    allowed = _scope_hosts(scope, "targets")
    excluded = _scope_hosts(scope, "exclusions")
    allowed_networks = _scope_networks(scope, "targets")
    excluded_networks = _scope_networks(scope, "exclusions")
    for candidate in extract_target_candidates(command):
        if candidate in excluded or _matches_network(candidate, excluded_networks):
            result.errors.append(f"excluded target {candidate} must not be touched")
        elif candidate in allowed or _matches_network(candidate, allowed_networks):
            continue
        elif _is_ip_network(candidate):
            result.errors.append(f"out-of-scope target {candidate} (not present in scope.yaml)")
        else:
            result.warnings.append(
                f"host {candidate} is not present in scope.yaml; verify authorization"
            )
    return result


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
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
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
    return token.startswith(_DEV_NETWORK_PREFIXES) or "://" in token


def _looks_like_local_path(token: str) -> bool:
    normalized = token.replace("\\", "/")
    return (
        normalized.startswith(("/", "./", "../", "~/", "$", "%"))
        or "/" in normalized
        or mimetypes.guess_type(normalized)[0] is not None
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


def _scope_hosts(scope: dict[str, Any], section: str) -> set[str]:
    values = scope.get(section, {}) or {}
    if section == "exclusions":
        return {normalise_target(value) for value in _values(values)}
    keys = ("ip_addresses", "in_scope_urls", "urls", "domains", "hostnames", "roles")
    return {normalise_target(value) for key in keys for value in _values(values.get(key, []))}


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


def _is_ip_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True
