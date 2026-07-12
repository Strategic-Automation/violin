#!/usr/bin/env python3
"""Lightweight Violin scope, command, and release guard.

Exit codes:
  0 = allowed / valid
  1 = blocked / invalid
  2 = review or explicit approval required
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on missing dependency
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
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
    (r"\bmkfs(\.|\\s|$)", "filesystem formatting is blocked"),
    (r"\bdd\s+if=.*\s+of=/dev/", "raw device writes are blocked"),
    (r"\bnc\s+.*\s-e\s+", "reverse shell payload is blocked"),
    (r"\bbash\s+-i\b", "interactive reverse shell pattern is blocked"),
    (r"/dev/tcp/[^/\s]+/\d+", "reverse shell TCP redirection pattern is blocked"),
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


def validate_scope_data(scope: dict[str, Any]) -> CheckResult:
    result = CheckResult()
    engagement = scope.get("engagement", {}) or {}
    targets = scope.get("targets", {}) or {}
    roe = scope.get("rules_of_engagement", {}) or {}
    auth = scope.get("authorisation", {}) or {}

    for field_name in ("client", "tester", "date", "duration"):
        if not str(engagement.get(field_name, "")).strip():
            result.add_error(f"engagement.{field_name} is required")

    target_values = []
    for key in ("domains", "ip_addresses", "cidrs", "urls"):
        target_values.extend(as_list(targets.get(key)))
    if not any(str(item).strip() for item in target_values):
        result.add_error("at least one target domain, IP, CIDR, or URL is required")

    if str(targets.get("app_type", "")).strip() == "":
        result.add_warning("targets.app_type is empty")

    if scope.get("mode") not in {"passive-recon", "active-recon", "standard-pentest", "exploit-validation"}:
        result.add_error("mode must be passive-recon, active-recon, standard-pentest, or exploit-validation")

    if scope.get("depth") not in {"black-box", "grey-box", "white-box"}:
        result.add_error("depth must be black-box, grey-box, or white-box")

    try:
        rate_limit = int(roe.get("max_requests_per_second", 0))
        if rate_limit <= 0:
            result.add_error("rules_of_engagement.max_requests_per_second must be positive")
        elif rate_limit > 20:
            result.add_warning("rate limit above 20 req/s requires explicit client approval")
    except (TypeError, ValueError):
        result.add_error("rules_of_engagement.max_requests_per_second must be an integer")

    forbidden = set(as_list(roe.get("forbidden_actions")))
    default_forbidden = {
        "credential-stuffing",
        "social-engineering",
        "persistence",
        "stealth-evasion",
        "malware-delivery",
        "destructive-payloads",
    }
    missing_forbidden = sorted(default_forbidden - forbidden)
    if missing_forbidden:
        result.add_warning(f"default forbidden actions missing: {', '.join(missing_forbidden)}")

    if auth.get("confirmed") is not True:
        result.add_error("authorisation.confirmed must be true before target interaction")
    if not str(auth.get("confirmed_by", "")).strip():
        result.add_error("authorisation.confirmed_by is required")
    if not str(auth.get("confirmed_at", "")).strip():
        result.add_error("authorisation.confirmed_at is required")

    if not result.errors and not result.warnings:
        result.add_info("scope is valid")
    return result


def validate_scope(args: argparse.Namespace) -> int:
    result = validate_scope_data(load_yaml(Path(args.scope)))
    result.print()
    return result.exit_code()


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def extract_hosts(command: str) -> set[str]:
    hosts: set[str] = set()
    for url in re.findall(r"https?://[^\s'\"<>]+", command, flags=re.IGNORECASE):
        host = host_from_url(url)
        if host:
            hosts.add(host)
    hosts.update(normalize_host(item) for item in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", command))
    for host in re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b", command):
        normalized = normalize_host(host)
        if not normalized.endswith((".txt", ".md", ".yaml", ".yml", ".json", ".py", ".sh", ".ps1")):
            hosts.add(normalized)
    return hosts


def has_allowed_carveout(scope: dict[str, Any], *needles: str) -> bool:
    allowed = " ".join(str(item).lower() for item in as_list((scope.get("rules_of_engagement") or {}).get("allowed_actions")))
    return any(needle in allowed for needle in needles)


def check_command(args: argparse.Namespace) -> int:
    scope = load_yaml(Path(args.scope))
    result = CheckResult()
    phase = args.phase.upper().replace("-", "_")
    command = args.command.strip()
    lowered = command.lower()

    if phase not in PHASES:
        result.add_error(f"unknown phase: {args.phase}")

    scope_result = validate_scope_data(scope)
    if scope_result.errors:
        result.errors.extend(f"scope invalid: {error}" for error in scope_result.errors)

    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            result.add_error(reason)

    for pattern, reason in TIER3_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            if "credential" in reason and has_allowed_carveout(scope, "credential", "brute", "password"):
                result.add_warning(f"{reason}; RoE carve-out found, require explicit per-command approval")
            else:
                result.add_warning(reason)

    tokens = command_tokens(command)
    tool = Path(tokens[0]).name.lower() if tokens else ""
    hosts = extract_hosts(command)

    if tool and tool not in TARGET_TOOLS and hosts:
        result.add_warning(f"command uses unclassified tool '{tool}' against detected target(s)")

    if tool in TARGET_TOOLS and not hosts:
        result.add_warning("target-touching tool used but no target was detected; ask for review")

    for host in sorted(hosts):
        if host in METADATA_TARGETS and not has_allowed_carveout(scope, "metadata", "ssrf"):
            result.add_error(f"cloud metadata target is not scoped by default: {host}")
        elif is_excluded_host(host, scope):
            result.add_error(f"target is explicitly excluded: {host}")
        elif not is_scoped_host(host, scope):
            result.add_error(f"target is outside approved scope: {host}")

    if phase in {"SCOPING", "REPORTING", "RETROSPECTIVE"} and (hosts or tool in TARGET_TOOLS):
        result.add_error(f"target interaction is not allowed during {phase}")

    if phase in {"RECON", "VULN_RESEARCH"} and any(term in lowered for term in ("--os-pwn", "--risk=3", "reverse shell")):
        result.add_error(f"exploit-style command is not allowed during {phase}")

    if not result.errors and not result.warnings:
        result.add_info("command is allowed by current lightweight guard")
    result.print()
    return result.exit_code()


def local_markdown_links(path: Path, text: str) -> list[str]:
    refs = set(re.findall(r"`([^`]+\.md)`", text))
    refs.update(match for match in re.findall(r"\]\(([^)]+\.md)\)", text) if "://" not in match)
    return sorted(refs)


def resolve_reference(base: Path, ref: str) -> Path:
    cleaned = ref.strip().split("#", 1)[0]
    if "$" in cleaned or "<" in cleaned:
        return Path()
    if cleaned.startswith("/"):
        return ROOT / cleaned.lstrip("/")
    if cleaned.startswith("skills/") or cleaned in {"README.md", "SOUL.md", "PLAN.md", ".hermes.md"}:
        return ROOT / cleaned
    if cleaned.startswith(("playbooks/", "references/")):
        skill_root = ROOT / "skills/pentest"
        if base.is_relative_to(skill_root):
            return base.parent / cleaned
        return skill_root / cleaned
    if cleaned.startswith("templates/"):
        return ROOT / "skills/pentest" / cleaned
    return base.parent / cleaned


def check_release(_: argparse.Namespace) -> int:
    result = CheckResult()
    for yaml_path in ("distribution.yaml", "config.yaml", "skills/pentest/templates/scope-template.yaml"):
        try:
            load_yaml(ROOT / yaml_path)
            result.add_info(f"YAML valid: {yaml_path}")
        except Exception as exc:  # noqa: BLE001 - report any validation failure
            result.add_error(f"YAML invalid: {yaml_path}: {exc}")

    distribution = load_yaml(ROOT / "distribution.yaml")
    for item in as_list(distribution.get("distribution_owned")):
        if not (ROOT / str(item)).exists():
            result.add_error(f"distribution_owned path missing: {item}")

    playbooks = sorted((ROOT / "skills/pentest/playbooks").glob("*.md"))
    if len(playbooks) != 31:
        result.add_error(f"expected 31 playbooks, found {len(playbooks)}")
    else:
        result.add_info("31 playbooks present")

    phase_playbooks = {"scoping", "recon", "vuln-research", "exploitation", "reporting", "tools", "post-exploitation"}
    for playbook in playbooks:
        text = playbook.read_text(encoding="utf-8")
        if playbook.stem not in phase_playbooks:
            for section in ("## Evidence", "## Stop", "## Blocked"):
                if section not in text:
                    result.add_error(f"{playbook.relative_to(ROOT)} missing {section}")
        if re.search(r"\./evidence\b|\./report\b", text):
            result.add_error(f"{playbook.relative_to(ROOT)} contains stale ./evidence or ./report path")

    for md_path in [ROOT / "README.md", ROOT / "SOUL.md", ROOT / ".hermes.md", ROOT / "skills/pentest/SKILL.md", *playbooks]:
        text = md_path.read_text(encoding="utf-8")
        for ref in local_markdown_links(md_path, text):
            resolved = resolve_reference(md_path, ref)
            if str(resolved) == ".":
                continue
            if not resolved.exists():
                result.add_error(f"{md_path.relative_to(ROOT)} references missing markdown file: {ref}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "fully autonomous" in readme.lower():
        result.add_error("README still claims fully autonomous operation")
    if "supervised agentic" not in readme.lower():
        result.add_warning("README does not use supervised agentic positioning")

    if not (ROOT / "scripts/smoke-test.ps1").exists():
        result.add_error("Windows smoke test missing: scripts/smoke-test.ps1")

    if not result.errors and not result.warnings:
        result.add_info("release check passed")
    result.print()
    return result.exit_code()


def main() -> int:
    parser = argparse.ArgumentParser(description="Violin lightweight safety and release guard")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    scope_parser = subparsers.add_parser("validate-scope", help="validate an engagement scope file")
    scope_parser.add_argument("--scope", required=True)
    scope_parser.set_defaults(func=validate_scope)

    command_parser = subparsers.add_parser("check-command", help="check a target-touching terminal command")
    command_parser.add_argument("--scope", required=True)
    command_parser.add_argument("--phase", required=True)
    command_parser.add_argument("--command", required=True)
    command_parser.set_defaults(func=check_command)

    release_parser = subparsers.add_parser("check-release", help="validate release readiness")
    release_parser.set_defaults(func=check_release)

    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should fail clearly
        print(f"BLOCK: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
