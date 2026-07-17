"""Typed command builders and read-only exploit search helpers.

Pure command construction — no execution.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from functools import lru_cache
from typing import Any

__all__ = [
    "build_httpx",
    "build_nuclei",
    "build_ffuf",
    "build_netcat_listener",
    "detect_netcat_variant",
    "search_exploit",
    "AdapterError",
]


class AdapterError(Exception):
    """Adapter validation error."""


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

    parts = ["httpx", "-u", _quote(target), "-json"]

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
            "message": "searchsploit is not installed or not on PATH",
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
