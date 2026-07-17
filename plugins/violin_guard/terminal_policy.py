"""Policy for the built-in Hermes terminal tool.

Violin keeps the built-in ``terminal`` tool available for host-local work, but
raw terminal calls must not become an escape hatch around the typed Violin
execution boundary.  This module is intentionally a conservative, pure
classifier: it blocks commands that are clearly target-touching and leaves
ordinary local development/bookkeeping commands available.

The typed ``violin_exec`` and ``violin_exec_burst`` tools remain the authoritative
path for target commands because they carry the engagement, scope, phase, PTT,
hypothesis, history, evidence, and sync arguments needed by the full guard.
"""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit

_TARGET_EXECUTABLES = frozenset(
    {
        "amass",
        "arp-scan",
        "crackmapexec",
        "dig",
        "enum4linux",
        "evil-winrm",
        "ffuf",
        "gobuster",
        "hakrawler",
        "hydra",
        "impacket-psexec",
        "ldapsearch",
        "masscan",
        "medusa",
        "mitmproxy",
        "msfconsole",
        "msfvenom",
        "ncat",
        "nc",
        "netexec",
        "nikto",
        "nmap",
        "nuclei",
        "onesixtyone",
        "rpcclient",
        "searchsploit",
        "smbclient",
        "socat",
        "sqlmap",
        "ssh",
        "sslscan",
        "subfinder",
        "telnet",
        "wfuzz",
        "whatweb",
        "wget",
        "curl",
    }
)

_SHELL_WRAPPERS = frozenset({"bash", "cmd", "fish", "powershell", "pwsh", "sh", "zsh"})
_COMMAND_WRAPPERS = frozenset({"docker", "doas", "podman", "sudo", "winpty"})
_SCRIPT_INTERPRETERS = _SHELL_WRAPPERS | {
    "node",
    "perl",
    "python",
    "python3",
    "ruby",
}
_PACKAGE_OR_SOURCE_COMMANDS = frozenset(
    {"cargo", "git", "go", "npm", "pip", "pip3", "pnpm", "uv", "yarn"}
)
_LOCAL_COMMANDS = frozenset(
    {
        "cat",
        "cmake",
        "cp",
        "date",
        "echo",
        "false",
        "hermes",
        "make",
        "mkdir",
        "mv",
        "printf",
        "pwd",
        "pytest",
        "rm",
        "touch",
        "true",
    }
)
_COMMAND_SPLIT_RE = re.compile(r"&&|\|\||[;|\n]")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b(?:https?|ftp|wss?|file)://[^\s'\"<>]+", re.IGNORECASE)
_KNOWN_SOURCE_HOST_RE = re.compile(
    r"https?://(?:[^/]*\.)?(?:github\.com|gitlab\.com|bitbucket\.org|"
    r"pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|"
    r"crates\.io|proxy\.golang\.org|go\.dev)(?::\d+)?(?:/|$)",
    re.IGNORECASE,
)
_NETWORK_PATH_RE = re.compile(r"/(?:dev/)?(?:tcp|udp)/", re.IGNORECASE)
_NETWORK_MODULE_RE = re.compile(
    r"\b(?:http\.server|requests|httpx|urllib(?:\.request)?|socket(?:server)?|scapy|paramiko)\b",
    re.IGNORECASE,
)
_SUSPICIOUS_SCRIPT_RE = re.compile(
    r"\b(?:attack|exploit|fuzz|payload|poc|probe|recon|scan|scanner)\b",
    re.IGNORECASE,
)
_LOCAL_FILE_SUFFIXES = frozenset(
    {".py", ".pyw", ".sh", ".bash", ".zsh", ".ps1", ".js", ".mjs", ".cjs", ".rb", ".pl"}
)


def _command_words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        # An incomplete quote is not a reason to let a possibly dangerous
        # command through.  The fallback is only used for classification.
        return re.findall(r"[^\s]+", segment)


def _basename(value: str) -> str:
    return re.split(r"[/\\]", value.rsplit("=", 1)[-1])[-1].lower()


def _first_executable(segment: str) -> str:
    words = _command_words(segment)
    index = 0
    while index < len(words):
        word = words[index]
        lower = word.lower()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", word):
            index += 1
            continue
        if lower in {"command", "env", "exec", "nice", "sudo", "timeout"}:
            index += 1
            if lower == "timeout" and index < len(words):
                index += 1
            continue
        return _basename(word)
    return ""


def _contains_target_executable(command: str) -> str | None:
    for segment in _COMMAND_SPLIT_RE.split(command):
        executable = _first_executable(segment)
        if executable in _TARGET_EXECUTABLES:
            return executable

        # Shell wrappers can hide the real command in `sh -c 'nmap ...'`.
        if executable in _SHELL_WRAPPERS:
            nested = _COMMAND_SPLIT_RE.split(segment, maxsplit=1)[-1]
            for target in _TARGET_EXECUTABLES:
                if re.search(rf"(?<![\w.-]){re.escape(target)}(?![\w.-])", nested, re.I):
                    return target

        # Privilege/container wrappers put the real executable later in the
        # argument list (for example ``sudo nmap`` or ``docker exec kali
        # nmap``).  Only inspect exact argv tokens here so ordinary commands
        # such as ``grep nmap`` remain usable.
        if executable in _COMMAND_WRAPPERS:
            for word in _command_words(segment)[1:]:
                candidate = _basename(word)
                if candidate in _TARGET_EXECUTABLES:
                    return candidate
    return None


def _is_package_or_source_command(command: str) -> bool:
    executable = _first_executable(command)
    return executable in _PACKAGE_OR_SOURCE_COMMANDS


def _url_hosts(command: str) -> list[str]:
    hosts: list[str] = []
    for match in _URL_RE.finditer(command):
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            host = None
        if host:
            hosts.append(host)
    return hosts


def _has_target_literal(command: str) -> bool:
    """Inspect shell arguments, not arbitrary source code or file paths."""
    for segment in _COMMAND_SPLIT_RE.split(command):
        words = _command_words(segment)
        executable = _first_executable(segment)
        skip_code = executable in _SCRIPT_INTERPRETERS and "-c" in words
        for index, word in enumerate(words):
            if skip_code and index > words.index("-c"):
                continue
            value = word.strip("'\"()[]{}<>,")
            if _IPV4_RE.fullmatch(value):
                return True
            if "://" in value:
                try:
                    if urlsplit(value).hostname:
                        return True
                except ValueError:
                    return True
                continue
            # Paths and ordinary local scripts are not host literals.  A bare
            # hostname remains meaningful for commands such as `ping host`.
            if "/" in value or "\\" in value or value.startswith("."):
                continue
            if any(value.lower().endswith(suffix) for suffix in _LOCAL_FILE_SUFFIXES):
                continue
            if _DOMAIN_RE.fullmatch(value):
                return True
    return False


def block_terminal_command(command: str) -> str | None:
    """Return a block message for clearly target-touching raw terminal calls.

    ``None`` means the command is host-local enough to remain available through
    the built-in terminal.  This is not a replacement for scope validation;
    it is the escape-hatch prevention layer that forces target work through the
    typed Violin tools.
    """
    if not isinstance(command, str) or not command.strip():
        return None

    target_executable = _contains_target_executable(command)
    if target_executable:
        return _message(
            f"target utility `{target_executable}` detected in the raw terminal command"
        )

    if _NETWORK_PATH_RE.search(command):
        return _message("network socket path detected in the raw terminal command")

    executable = _first_executable(command)
    if executable in _SCRIPT_INTERPRETERS and _NETWORK_MODULE_RE.search(command):
        return _message("network-capable script primitive detected in the raw terminal command")

    # Package/source retrieval is allowed for local setup (for example git
    # clone or pip install).  URLs and host literals in all other commands are
    # treated as target interaction and must use the typed guard.
    url_hosts = _url_hosts(command)
    if not _is_package_or_source_command(command) and url_hosts:
        return _message("URL detected in a non-package raw terminal command")

    # Public package/source URLs are host-local setup, not assessment traffic.
    # Keep numeric authorities conservative: a clone/install from an IP may be
    # an engagement target and must go through the typed guard.
    if (
        _is_package_or_source_command(command)
        and url_hosts
        and _KNOWN_SOURCE_HOST_RE.search(command)
        and not _IPV4_RE.search(command)
    ):
        return None

    if executable not in _LOCAL_COMMANDS and _has_target_literal(command):
        return _message("target host literal detected in the raw terminal command")

    if executable in _SCRIPT_INTERPRETERS and _SUSPICIOUS_SCRIPT_RE.search(command):
        return _message("assessment script detected in the raw terminal command")

    return None


def _message(reason: str) -> str:
    return (
        "RAW TERMINAL TARGET EXECUTION BLOCKED by Violin: "
        f"{reason}. Use `violin_exec` for one command or `violin_exec_burst` "
        "for a bounded batch so scope, phase, PTT, hypotheses, history, "
        "evidence, and sync gates are enforced. The built-in terminal remains "
        "available for host-local preparation, tests, builds, and bookkeeping."
    )


__all__ = ["block_terminal_command"]
