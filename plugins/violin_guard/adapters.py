"""Typed command builders and read-only exploit search helpers.

Pure command construction — no execution.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = [
    "available",
    "ToolAvailability",
    "build_httpx",
    "build_nuclei",
    "build_ffuf",
    "resolve_ffuf_wordlist",
    "build_netcat_listener",
    "detect_netcat_variant",
    "is_projectdiscovery_httpx",
    "search_exploit",
    "AdapterError",
]


class AdapterError(Exception):
    """Adapter validation error."""


@dataclass(frozen=True)
class ToolAvailability:
    """Read-only result from an installed-tool probe."""

    available: bool
    tool: str
    backend: str
    path: str = ""
    message: str = ""


def is_projectdiscovery_httpx(output: str) -> bool:
    """Classify whether a help/version string belongs to ProjectDiscovery httpx."""
    text = output.lower()
    return any(
        k in text for k in ("projectdiscovery", "status-code", "tech-detect", "follow-redirects")
    )


@lru_cache(maxsize=8)
def _installed_httpx_binary() -> str:
    """Resolve ProjectDiscovery httpx binary ('httpx-toolkit' or 'httpx')."""
    if shutil.which("httpx-toolkit"):
        return "httpx-toolkit"

    path = shutil.which("httpx")
    if path:
        try:
            res = subprocess.run(
                [path, "-h"], capture_output=True, text=True, timeout=5, check=False
            )
            if is_projectdiscovery_httpx(f"{res.stdout}\n{res.stderr}"):
                return "httpx"
            raise AdapterError(
                "httpx on PATH is Python httpx HTTP client, not ProjectDiscovery httpx scanner. "
                "Use curl/nmap/whatweb instead."
            )
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(f"failed probing httpx binary: {exc}") from exc

    raise AdapterError("httpx is not installed or not on PATH")


def available(tool: str, backend: str = "local") -> ToolAvailability:
    """Report whether a CLI tool can be resolved without touching a target."""

    name = str(tool or "").strip()
    if not name or any(char.isspace() for char in name):
        raise AdapterError("tool must be one executable name")
    if backend != "local":
        raise AdapterError("availability probes currently support the local backend only")

    if name == "httpx":
        if not (shutil.which("httpx-toolkit") or shutil.which("httpx")):
            return ToolAvailability(
                False,
                "httpx",
                backend,
                message="httpx is not installed or not on PATH",
            )
        try:
            bin_name = _installed_httpx_binary()
            path = shutil.which(bin_name) or shutil.which("httpx") or ""
            return ToolAvailability(
                True, bin_name, backend, path=path, message=f"{bin_name} is available"
            )
        except AdapterError as exc:
            return ToolAvailability(
                False,
                "httpx",
                backend,
                path=shutil.which("httpx") or "",
                message=str(exc),
            )

    path = shutil.which(name)
    if path:
        return ToolAvailability(True, name, backend, path=path, message=f"{name} is available")
    return ToolAvailability(
        False,
        name,
        backend,
        message=f"{name} is not installed or not on PATH",
    )


def _quote(value: Any) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise AdapterError("adapter values must be single-line text")
    return shlex.quote(text)


def _extra(values: Any) -> str:
    items = values or []
    if not isinstance(items, list) or len(items) > 20:
        raise AdapterError("extra_args must be an array of at most 20 arguments")
    return " ".join(_quote(item) for item in items)


def build_httpx(args: dict) -> str:
    """Build httpx command: target, extra_args."""
    target = args.get("target")
    if not target:
        raise AdapterError("target is required")

    bin_name = _installed_httpx_binary()
    parts = [bin_name, "-u", _quote(target), "-json"]

    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)

    return " ".join(parts)


def build_nuclei(args: dict) -> str:
    """Build nuclei command: target, templates, severity, extra_args."""
    target = args.get("target")
    if not target:
        raise AdapterError("target is required")

    parts = ["nuclei", "-u", _quote(target), "-jsonl"]

    if args.get("templates"):
        parts.extend(["-t", _quote(args["templates"])])

    if args.get("severity"):
        severity = str(args["severity"]).lower()
        if not re.fullmatch(
            r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*",
            severity,
        ):
            raise AdapterError("invalid severity list")
        parts.extend(["-severity", severity])

    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)

    return " ".join(parts)


def build_ffuf(args: dict) -> str:
    """Build ffuf command: url (with FUZZ), wordlist, headers, extra_args."""
    url = args.get("url") or args.get("target")
    wordlist = args.get("wordlist")

    if not url or not wordlist:
        raise AdapterError("url and wordlist are required")

    if "FUZZ" not in str(url):
        raise AdapterError("ffuf url must contain the FUZZ marker")

    parts = ["ffuf", "-u", _quote(url), "-w", _quote(wordlist), "-json"]

    for header in args.get("headers") or []:
        parts.extend(["-H", _quote(header)])

    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)

    return " ".join(parts)


def resolve_ffuf_wordlist(requested: object = "", eng_dir: object = "") -> str:
    """Resolve an ffuf wordlist across common Kali, Parrot, custom installs, and engagement evidence."""

    candidates: list[Path] = []
    requested_text = os.path.expandvars(str(requested or "").strip())
    if requested_text:
        candidates.append(Path(requested_text).expanduser())

    eng_text = os.path.expandvars(
        str(
            eng_dir or os.environ.get("ENG_DIR", "") or os.environ.get("VIOLIN_ENG_ROOT", "")
        ).strip()
    )
    if eng_text:
        eng_path = Path(eng_text).expanduser()
        candidates.extend(
            (
                eng_path / "evidence" / "recon" / "focused_wordlist.txt",
                eng_path / "evidence" / "recon" / "wordlist.txt",
                eng_path / "evidence" / "wordlist.txt",
            )
        )

    seclists_root = os.environ.get("SECLISTS", "").strip()
    if seclists_root:
        candidates.append(
            Path(os.path.expandvars(seclists_root)).expanduser()
            / "Discovery"
            / "Web-Content"
            / "common.txt"
        )
    candidates.extend(
        (
            Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
            Path("/usr/share/dirb/wordlists/common.txt"),
            Path("/usr/share/wordlists/dirb/common.txt"),
        )
    )

    checked: list[str] = []
    for candidate in candidates:
        candidate_text = str(candidate)
        if candidate_text in checked:
            continue
        checked.append(candidate_text)
        if candidate.is_file():
            return candidate_text

    locations = ", ".join(checked)
    raise AdapterError(
        "ffuf wordlist not found; checked "
        f"{locations}. Pass an existing wordlist, install the seclists package, "
        "or set SECLISTS to a SecLists checkout. A target-derived focused wordlist "
        "is also acceptable when recorded in engagement evidence."
    )


def detect_netcat_variant(version_output: str) -> str:
    """Classify a netcat implementation from one captured help/version output."""

    normalized = version_output.lower()
    if "ncat" in normalized and "nmap" in normalized:
        return "ncat"
    if "openbsd" in normalized:
        return "openbsd"
    if "v1.10" in normalized or "hobbit" in normalized or "traditional" in normalized:
        return "traditional"
    raise AdapterError(
        "unsupported netcat implementation; expected OpenBSD nc, traditional nc, or Ncat"
    )


@lru_cache(maxsize=8)
def _installed_netcat_variant(binary: str) -> tuple[str, str]:
    """Detect one installed binary once; never probe individual flags."""

    path = shutil.which(binary)
    if not path:
        raise AdapterError(f"{binary} is not installed or not on PATH")
    result = subprocess.run(
        [path, "-h"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    return path, detect_netcat_variant(output)


def _listener_port(args: dict) -> int:
    try:
        port = int(args.get("port"))
    except (TypeError, ValueError) as exc:
        raise AdapterError("listener port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise AdapterError("listener port must be between 1 and 65535")
    return port


def _listener_identity(args: dict) -> tuple[str, str]:
    binary = str(args.get("binary") or "nc")
    variant = str(args.get("variant") or "").lower()
    if not variant:
        return _installed_netcat_variant(binary)
    if variant not in {"openbsd", "traditional", "ncat"}:
        raise AdapterError("variant must be openbsd, traditional, or ncat")
    return binary, variant


def _openbsd_listener(path: str, port: int, bind_host: str, keep_open: bool) -> list[str]:
    parts = [path, "-l", "-v"]
    if keep_open:
        parts.append("-k")
    if bind_host:
        parts.extend(["-s", bind_host])
    return [*parts, str(port)]


def _traditional_listener(path: str, port: int, bind_host: str, keep_open: bool) -> list[str]:
    if keep_open:
        raise AdapterError("traditional nc has no supported keep-open flag")
    parts = [path, "-l", "-v", "-p", str(port)]
    if bind_host:
        parts.extend(["-s", bind_host])
    return parts


def _ncat_listener(path: str, port: int, bind_host: str, keep_open: bool) -> list[str]:
    parts = [path, "--listen", "--verbose"]
    if keep_open:
        parts.append("--keep-open")
    if bind_host:
        parts.append(bind_host)
    return [*parts, str(port)]


_LISTENER_BUILDERS = {
    "openbsd": _openbsd_listener,
    "traditional": _traditional_listener,
    "ncat": _ncat_listener,
}


def build_netcat_listener(args: dict) -> str:
    """Build a deterministic listener command for a known netcat family."""

    port = _listener_port(args)
    path, variant = _listener_identity(args)
    bind_host = str(args.get("bind_host") or "").strip()
    parts = _LISTENER_BUILDERS[variant](path, port, bind_host, bool(args.get("keep_open")))
    return " ".join(_quote(part) for part in parts)


def search_exploit(args: dict) -> dict[str, Any]:
    """Search local ExploitDB via searchsploit --json."""
    query = " ".join(
        str(args.get(key) or "").strip() for key in ("product", "version", "service", "cve")
    ).strip()

    if not query:
        raise AdapterError("provide product, version, service, or cve")

    binary = shutil.which("searchsploit")
    if not binary:
        return {
            "available": False,
            "tool": "searchsploit",
            "message": "searchsploit is not installed or not on PATH; install exploitdb via 'apt install exploitdb'",
            "candidates": [],
            "online_corroboration_required": True,
            "executed_candidates": False,
        }

    result = subprocess.run(
        [binary, "--json", query],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    if result.returncode not in (0, 1):
        raise AdapterError(result.stderr.strip() or "searchsploit failed")

    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise AdapterError("searchsploit returned malformed JSON") from exc

    rows = []
    for source in (payload.get("RESULTS_EXPLOIT", []), payload.get("RESULTS_SHELLCODE", [])):
        if isinstance(source, list):
            rows.extend(source)

    seen: set[tuple[str, str]] = set()
    candidates = []

    for row in rows:
        title = str(row.get("Title") or row.get("title") or "").strip()
        path = str(row.get("Path") or row.get("path") or "").strip()
        key = (title, path)
        if not title or key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "title": title,
                "path": path,
                "platform": row.get("Platform") or row.get("platform"),
                "type": row.get("Type") or row.get("type"),
                "identifiers": [v for v in (args.get("cve"),) if v],
                "provenance": "local-searchsploit",
            }
        )

    return {
        "available": True,
        "tool": "searchsploit",
        "query": query,
        "candidates": candidates,
        "online_corroboration_required": True,
        "executed_candidates": False,
    }
