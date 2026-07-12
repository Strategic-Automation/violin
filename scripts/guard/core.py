"""Shared types, constants, and scope host helpers for the Violin guard package."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on missing dependency
    yaml = None

# scripts/guard/core.py -> parents[2] == repo root
ROOT = Path(__file__).resolve().parents[2]

# Single source of truth for the engagement root. The skill (SKILL.md /
# scoping.md) and the violin-guard plugin MUST resolve every engagement
# directory against the SAME absolute base, otherwise the two trees diverge
# and a stale lock in one tree wedges the other (see root-cause report).
#
# Resolution order (first match wins):
#   1. $VIOLIN_ENG_ROOT  - explicit override (absolute or relative-to-cwd)
#   2. <repo>/engagements - default canonical location
# Engagements are ALWAYS "<host>-<YYYY-MM-DD>" subdirs of ENG_ROOT.
ENG_ROOT = Path(os.environ.get("VIOLIN_ENG_ROOT", ROOT / "engagements")).resolve()

# Backwards-compat alias used by older call sites (bootstrap.py auto-repair
# messages etc.). Equal to ENG_ROOT.
_REPO_ENGAGEMENTS = ENG_ROOT


def resolve_eng_dir(eng_dir: str | Path | None) -> str:
    """Resolve an engagement directory to an ABSOLUTE path under ENG_ROOT.

    The skill builds trees with a relative ``engagements/<host>-<date>`` string
    while the plugin historically resolved that relative path against Hermes
    home (CWD), producing two divergent trees. This function makes both entry
    points converge on the same canonical absolute root no matter what the
    caller passes:

      - None / ""            -> ENG_ROOT itself (useful for listing engagements)
      - "<host>-<date>"      -> ENG_ROOT / "<host>-<date>"
      - "engagements/..."    -> ENG_ROOT / "..."   (the relative form the skill
                                                     used; the ``engagements/``
                                                     prefix is stripped, not
                                                     nested, so both trees merge)
      - absolute path        -> passed through unchanged (already explicit)
      - a path already under ENG_ROOT -> returned as-is

    Returns an absolute ``str`` path.
    """
    eng_dir = "" if eng_dir is None else str(eng_dir).strip()
    if not eng_dir:
        return str(ENG_ROOT)
    p = Path(eng_dir)
    if p.is_absolute():
        return str(p.resolve())
    # Normalise "engagements/foo" and "engagements/foo/bar" -> just the tail,
    # so the skill's relative form lands in ENG_ROOT, not ENG_ROOT/engagements.
    parts = p.parts
    if parts and parts[0] == "engagements":
        parts = parts[1:]
    if not parts:
        return str(ENG_ROOT)
    return str(ENG_ROOT.joinpath(*parts))


PHASES = {"SCOPING", "RECON", "VULN_RESEARCH", "EXPLOITATION", "REPORTING", "RETROSPECTIVE"}

TARGET_TOOLS = {
    "amass",
    "arjun",
    "commix",
    "curl",
    "dalfox",
    "dig",
    "dirb",
    "dirsearch",
    "ffuf",
    "feroxbuster",
    "gobuster",
    "host",
    "httpx",
    "hydra",
    "masscan",
    "nmap",
    "nikto",
    "nslookup",
    "nuclei",
    "sqlmap",
    "subfinder",
    "testssl",
    "whatweb",
    "wpscan",
    "xsstrike",
    "zap-baseline.py",
}

DANGEROUS_PATTERNS = [
    (r"\bsqlmap\b.*\s--dump\b", "sqlmap data dumping is blocked by default"),
    (r"\bsqlmap\b.*\s--os-shell\b", "sqlmap OS shell is blocked"),
    (r"\bsqlmap\b.*\s--file-(read|write)\b", "sqlmap file read/write is blocked by default"),
    (r"\bDROP\s+(TABLE|DATABASE)\b", "destructive SQL payload is blocked"),
    (r"\brm\s+-rf\s+(/|\*)", "destructive filesystem deletion is blocked"),
    (r"\bmkfs(\.|\s|$)", "filesystem formatting is blocked"),
    (r"\bdd\s+if=.*\s+of=/dev/", "raw device writes are blocked"),
    (r"\b(meterpreter|msfvenom)\b", "payload generation or meterpreter requires explicit review"),
]

TIER3_PATTERNS = [
    (r"\b(hydra|medusa|patator|hashcat|john)\b", "credential attack or cracking tool requires RoE carve-out"),
    (r"\b(masscan|zmap)\b", "high-volume scanning requires phase approval and rate limits"),
    (r"\b--rate\s+[1-9]\d{2,}\b", "high request rate requires approval"),
    (r"\b--threads\s+[5-9]\d*\b", "high concurrency requires approval"),
    (r"\b--forms\b|\b--crawl\b", "broad authenticated crawling requires approval"),
]

METADATA_TARGETS = {
    "169.254.169.254",
    "100.100.100.200",
    "metadata.google.internal",
    "fd00:ec2::254",
}


@dataclass
class CheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def add_info(self, message: str) -> None:
        self.infos.append(message)

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0

    def print(self) -> None:
        for message in self.errors:
            print(f"BLOCK: {message}")
        for message in self.warnings:
            print(f"REVIEW: {message}")
        for message in self.infos:
            print(f"OK: {message}")


def load_yaml(path: Path) -> Any:
    if yaml is None:
        raise RuntimeError("PyYAML is required. Install with: python -m pip install pyyaml")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_host(value: str) -> str:
    return value.strip().strip("[]").strip(".").lower()


def validate_scope_data(scope: dict[str, Any]) -> CheckResult:
    """Validate an engagement scope dictionary.

    Checks for at least one target, valid CIDRs, and (as warnings) the
    presence of authorized parties, rules of engagement, and date bounds.
    """
    result = CheckResult()
    targets = scope.get("targets", {}) or {}
    exclusions = scope.get("exclusions", {}) or {}

    domains = [normalize_host(d) for d in as_list(targets.get("domains"))]
    ip_addresses = [normalize_host(i) for i in as_list(targets.get("ip_addresses"))]
    cidrs = as_list(targets.get("cidrs", []))
    urls = as_list(targets.get("urls"))

    # normalise and de-duplicate the host set
    hosts: set[str] = set()
    hosts.update(domains)
    hosts.update(ip_addresses)
    for url in urls:
        host = host_from_url(str(url))
        if host:
            hosts.add(host)
    for item in cidrs:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            result.add_error(f"scope invalid: cidr is not a valid network: {item}")

    if not hosts and not cidrs:
        result.add_error("scope invalid: no targets defined in targets.domains / ip_addresses / urls")

    if not as_list(scope.get("authorized_parties")):
        result.add_warning("scope warning: no authorized_parties listed; confirm authorization before testing")

    if not (scope.get("rules_of_engagement") or {}).get("allowed_actions"):
        result.add_warning("scope warning: no rules_of_engagement.allowed_actions defined")

    if scope.get("start_date") and scope.get("end_date"):
        result.add_warning("scope warning: dates present but not range-checked")

    return result


def host_from_url(value: str) -> str | None:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return normalize_host(parsed.hostname or "")


def get_targets(scope: dict[str, Any]) -> tuple[set[str], set[str], list[ipaddress._BaseNetwork], set[str]]:
    targets = scope.get("targets", {}) or {}
    domains = {normalize_host(str(item)) for item in as_list(targets.get("domains")) if str(item).strip()}
    ip_addresses = {normalize_host(str(item)) for item in as_list(targets.get("ip_addresses")) if str(item).strip()}
    networks: list[ipaddress._BaseNetwork] = []
    for item in as_list(targets.get("cidrs")):
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    url_hosts = {host_from_url(str(item)) for item in as_list(targets.get("urls")) if str(item).strip()}
    return domains, ip_addresses, networks, {host for host in url_hosts if host}


def get_exclusions(scope: dict[str, Any]) -> tuple[set[str], set[str], list[ipaddress._BaseNetwork], set[str]]:
    exclusions = scope.get("exclusions", {}) or {}
    domains = {normalize_host(str(item)) for item in as_list(exclusions.get("domains")) if str(item).strip()}
    ip_addresses = {normalize_host(str(item)) for item in as_list(exclusions.get("ip_addresses")) if str(item).strip()}
    networks: list[ipaddress._BaseNetwork] = []
    for item in as_list(exclusions.get("cidrs")):
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    url_hosts = {host_from_url(str(item)) for item in as_list(exclusions.get("urls")) if str(item).strip()}
    return domains, ip_addresses, networks, {host for host in url_hosts if host}


def domain_matches(host: str, domains: set[str]) -> bool:
    host = normalize_host(host)
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


def ip_matches(host: str, addresses: set[str], networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return host in addresses or any(ip in network for network in networks)


def is_scoped_host(host: str, scope: dict[str, Any]) -> bool:
    domains, ips, networks, url_hosts = get_targets(scope)
    return domain_matches(host, domains | url_hosts) or ip_matches(host, ips, networks)


def is_excluded_host(host: str, scope: dict[str, Any]) -> bool:
    domains, ips, networks, url_hosts = get_exclusions(scope)
    return domain_matches(host, domains | url_hosts) or ip_matches(host, ips, networks)
