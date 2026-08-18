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

import contextlib
import ipaddress
import re
from urllib.parse import urlsplit

from ..core.bash_ast import CommandSegment, parse_bash_segments

# ---------------------------------------------------------------------------
# Rule Sets & Pattern Definitions
# ---------------------------------------------------------------------------

_SHELL_WRAPPERS = frozenset({"bash", "cmd", "fish", "powershell", "pwsh", "sh", "zsh"})
_SCRIPT_INTERPRETERS = _SHELL_WRAPPERS | {
    "node",
    "perl",
    "python",
    "python3",
    "ruby",
}
_PACKAGE_OR_SOURCE_COMMANDS = frozenset(
    {"cargo", "curl", "fetch", "git", "go", "npm", "pip", "pip3", "pnpm", "uv", "wget", "yarn"}
)
_LOCAL_COMMANDS = frozenset(
    {
        "awk",
        "cat",
        "cmake",
        "cp",
        "date",
        "diff",
        "dir",
        "echo",
        "false",
        "find",
        "grep",
        "head",
        "hermes",
        "ls",
        "make",
        "mkdir",
        "mv",
        "printf",
        "pwd",
        "pytest",
        "rg",
        "ripgrep",
        "rm",
        "sed",
        "sort",
        "tail",
        "touch",
        "true",
        "uniq",
        "wc",
    }
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b(?:https?|ftp|wss?|file)://[^\s'\"<>]+", re.IGNORECASE)
_KNOWN_SOURCE_HOSTS = frozenset(
    {
        "bitbucket.org",
        "crates.io",
        "files.pythonhosted.org",
        "gist.github.com",
        "gist.githubusercontent.com",
        "github.com",
        "gitlab.com",
        "go.dev",
        "objects.githubusercontent.com",
        "proxy.golang.org",
        "pypi.org",
        "raw.githubusercontent.com",
        "registry.npmjs.org",
    }
)
_NETWORK_PATH_RE = re.compile(r"/(?:dev/)?(?:tcp|udp)/", re.IGNORECASE)
_UNC_PATH_RE = re.compile(
    r"(?<![:\w])(?:\\\\|//)(?![./])(?:\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*)(?:[\\/])",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(r"(?<![\w])([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]?)([^\s;|&]+)\2")
_NETWORK_MODULE_RE = re.compile(
    r"\b(?:http\.server|requests|httpx|urllib(?:\.request)?|socket(?:server)?|scapy|paramiko)\b",
    re.IGNORECASE,
)
_COMMAND_SUBSTITUTION_RE = re.compile(r"\$\(|`")
_SUSPICIOUS_SCRIPT_RE = re.compile(
    r"\b(?:attack|exploit|fuzz|payload|poc|probe|recon|scan|scanner)\b",
    re.IGNORECASE,
)
_LOCAL_FILE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyw",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".js",
        ".mjs",
        ".cjs",
        ".rb",
        ".pl",
        ".log",
        ".txt",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".csv",
        ".tsv",
        ".out",
        ".err",
        ".dat",
        ".conf",
        ".cfg",
        ".ini",
        ".md",
    }
)


# ---------------------------------------------------------------------------
# Classifier Logic
# ---------------------------------------------------------------------------


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


def _is_known_source_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    return any(
        normalized == known or normalized.endswith(f".{known}") for known in _KNOWN_SOURCE_HOSTS
    )


def _word_is_target_literal(word: str) -> bool:
    """Inspect a single shell word token for an IP address, remote URL, or domain literal."""
    value = word.strip("'\"()[]{}<>,")
    authority = value.rsplit("@", 1)[-1]
    if authority.count(":") == 1:
        authority = authority.split(":", 1)[0]

    if _IPV4_RE.fullmatch(authority):
        return authority not in {"127.0.0.1", "0.0.0.0"}

    with contextlib.suppress(ValueError):
        clean_ip = authority.strip("[]")
        ip_obj = ipaddress.ip_address(clean_ip)
        return not ip_obj.is_loopback and not ip_obj.is_unspecified

    if "://" in value:
        try:
            hostname = urlsplit(value).hostname
            return bool(
                hostname and hostname.lower() not in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
            )
        except ValueError:
            return True

    # Paths and ordinary local scripts are not host literals
    if "/" in value or "\\" in value or value.startswith("."):
        return False
    if authority.lower() in {"localhost"}:
        return False
    if any(value.lower().endswith(suffix) for suffix in _LOCAL_FILE_SUFFIXES):
        return False

    return bool(_DOMAIN_RE.fullmatch(authority))


def _has_target_literal_in_segment(seg: CommandSegment) -> bool:
    """Inspect shell arguments extracted from AST."""
    words = seg.words
    executable = seg.executable
    skip_code = (
        executable in _SCRIPT_INTERPRETERS and executable not in _SHELL_WRAPPERS and "-c" in words
    )
    c_index = words.index("-c") if skip_code else -1
    for index, word in enumerate(words):
        if skip_code and index > c_index:
            continue
        if _word_is_target_literal(word):
            return True
    return False


def _is_violin_init_command(seg: CommandSegment) -> bool:
    """Return whether ``seg`` invokes Violin's host-local bootstrap command."""
    if seg.executable not in {"python", "python3"}:
        return False
    words = seg.words
    for index, word in enumerate(words):
        script = word.replace("\\", "/").removeprefix("./")
        if (
            (script == "scripts/violin_guard.py" or script.endswith("/scripts/violin_guard.py"))
            and index + 1 < len(words)
            and words[index + 1] == "init-engagement"
        ):
            return True
    return False


def _dynamic_init_host(seg: CommandSegment) -> bool:
    """Reject host indirection while allowing variables in local path arguments."""
    words = seg.words
    for index, word in enumerate(words):
        if word == "--host" and index + 1 < len(words):
            return "$" in words[index + 1] or "`" in words[index + 1]
        if word.startswith("--host="):
            host = word.partition("=")[2]
            return "$" in host or "`" in host
    return False


def _is_local_compilation_or_test(seg: CommandSegment) -> bool:
    """Return True if the command is a local syntax compile check or test framework invocation."""
    words = seg.words
    lower_words = [word.lower() for word in words]
    if "-m" in lower_words:
        idx = lower_words.index("-m")
        if idx + 1 < len(lower_words) and lower_words[idx + 1] in {
            "py_compile",
            "pytest",
            "unittest",
            "doctest",
        }:
            return True
    return "py_compile" in seg.raw_text or "pytest" in lower_words or "unittest" in lower_words


def _is_local_package_import_check(seg: CommandSegment) -> bool:
    """Return True if command is a local package availability probe (e.g. python3 -c 'import requests')."""
    if seg.executable not in _SCRIPT_INTERPRETERS:
        return False
    if _url_hosts(seg.raw_text) or _IPV4_RE.search(seg.raw_text):
        return False
    text = seg.raw_text.strip()
    return bool(re.search(r"""(?:python|python3)\s+-c\s+["']\s*import\s+[\w\s,.]+\s*["']""", text))


def _block_terminal_segment(seg: CommandSegment) -> str | None:
    segment_text = seg.raw_text
    executable = seg.executable

    if _NETWORK_PATH_RE.search(segment_text):
        return _message("network socket path detected in the raw terminal command")
    if _UNC_PATH_RE.search(segment_text):
        return _message("UNC or network-share path detected in the raw terminal command")

    if (
        executable in _SCRIPT_INTERPRETERS
        and _NETWORK_MODULE_RE.search(segment_text)
        and not _is_local_package_import_check(seg)
    ):
        return _message("network-capable script primitive detected in the raw terminal command")

    # Package/source retrieval is allowed for local setup (for example git
    # clone or pip install).  URLs and host literals in all other commands are
    # treated as target interaction and must use the typed guard.
    is_source_command = executable in _PACKAGE_OR_SOURCE_COMMANDS
    url_hosts = _url_hosts(segment_text)
    if not is_source_command and executable not in _LOCAL_COMMANDS and url_hosts:
        return _message("URL detected in a non-local raw terminal command: " + ", ".join(url_hosts))

    # Public package/source URLs are host-local setup, not assessment traffic.
    # Keep numeric authorities conservative: a clone/install from an IP may be
    # an engagement target and must go through the typed guard.
    if (
        is_source_command
        and url_hosts
        and all(_is_known_source_host(host) for host in url_hosts)
        and not _IPV4_RE.search(segment_text)
    ):
        return None

    # ``init-engagement`` writes local workspace files and creates no network
    # traffic, so its scope host may be provided directly. Keep the exception
    # narrow: other guard subcommands still use the normal classifier, and
    # target values hidden behind shell expansion remain blocked.
    if _is_violin_init_command(seg):
        if _COMMAND_SUBSTITUTION_RE.search(segment_text) or _dynamic_init_host(seg):
            return _message(
                "dynamic init-engagement host detected; pass --host directly without "
                "shell or file indirection"
            )
        return None

    if executable not in _LOCAL_COMMANDS and _has_target_literal_in_segment(seg):
        return _message("target host literal detected in the raw terminal command")

    if (
        executable in _SCRIPT_INTERPRETERS
        and _SUSPICIOUS_SCRIPT_RE.search(segment_text)
        and not _is_local_compilation_or_test(seg)
    ):
        return _message("assessment script detected in the raw terminal command")

    return None


def block_terminal_command(command: str) -> str | None:
    """Return a block message for clearly target-touching raw terminal calls."""
    if not isinstance(command, str) or not command.strip():
        return None

    tainted_variables = {
        name
        for name, _quote, value in _ASSIGNMENT_RE.findall(command)
        if _word_is_target_literal(value)
    }
    for segment in parse_bash_segments(command):
        if (
            tainted_variables
            and segment.executable not in _LOCAL_COMMANDS
            and any(
                re.search(rf"\$(?:{{{re.escape(name)}}}|{re.escape(name)}\b)", segment.raw_text)
                for name in tainted_variables
            )
        ):
            return _message("target-bearing shell variable used by a non-local command")
        if message := _block_terminal_segment(segment):
            return message
    return None


def _message(reason: str) -> str:
    return (
        "RAW TERMINAL TARGET EXECUTION BLOCKED by Violin: "
        f"{reason}. Use `violin_exec` or `violin_exec_burst` to run on the engagement backend (typed tool wrappers)"
        "for any target command so scope, phase, PTT, hypotheses, history, "
        "evidence, and sync gates are enforced. The built-in terminal remains "
        "available for host-local preparation, tests, builds, and bookkeeping."
    )


__all__ = ["block_terminal_command"]
