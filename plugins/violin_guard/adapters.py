"""Typed command builders and read-only exploit search helpers."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from typing import Any


def _quote(value: Any) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ValueError("adapter values must be single-line text")
    return shlex.quote(text)


def _extra(values: Any) -> str:
    items = values or []
    if not isinstance(items, list) or len(items) > 20:
        raise ValueError("extra_args must be an array of at most 20 arguments")
    return " ".join(_quote(item) for item in items)


def build_nmap(args: dict) -> str:
    target = args.get("target")
    if not target:
        raise ValueError("target is required")
    scan_type = args.get("scan_type", "-sCV")
    if scan_type not in {"-sV", "-sC", "-sCV", "-sn", "-Pn"}:
        raise ValueError("unsupported scan_type")
    parts = ["nmap", scan_type]
    if args.get("ports"):
        if not re.fullmatch(r"[0-9,-]+", str(args["ports"])):
            raise ValueError("ports must contain only digits, commas, and hyphens")
        parts.extend(["-p", str(args["ports"])])
    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)
    parts.append(_quote(target))
    return " ".join(parts)


def build_httpx(args: dict) -> str:
    target = args.get("target")
    if not target:
        raise ValueError("target is required")
    parts = ["httpx", "-u", _quote(target), "-json"]
    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)
    return " ".join(parts)


def build_nuclei(args: dict) -> str:
    target = args.get("target")
    if not target:
        raise ValueError("target is required")
    parts = ["nuclei", "-u", _quote(target), "-jsonl"]
    if args.get("templates"):
        parts.extend(["-t", _quote(args["templates"])])
    if args.get("severity"):
        severity = str(args["severity"]).lower()
        if not re.fullmatch(
            r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*", severity
        ):
            raise ValueError("invalid severity list")
        parts.extend(["-severity", severity])
    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)
    return " ".join(parts)


def build_ffuf(args: dict) -> str:
    url = args.get("url") or args.get("target")
    wordlist = args.get("wordlist")
    if not url or not wordlist:
        raise ValueError("url and wordlist are required")
    if "FUZZ" not in str(url):
        raise ValueError("ffuf url must contain the FUZZ marker")
    parts = ["ffuf", "-u", _quote(url), "-w", _quote(wordlist), "-json"]
    for header in args.get("headers") or []:
        parts.extend(["-H", _quote(header)])
    extra = _extra(args.get("extra_args"))
    if extra:
        parts.append(extra)
    return " ".join(parts)


BUILDERS = {
    "nmap": build_nmap,
    "httpx": build_httpx,
    "nuclei": build_nuclei,
    "ffuf": build_ffuf,
}


def available(tool: str, backend: str, container: str = "kali-pentest") -> tuple[bool, str]:
    if backend == "local":
        path = shutil.which(tool)
        return bool(path), path or f"{tool} is not installed or not on PATH"
    if backend != "docker":
        return False, "backend must be local or docker"
    if shutil.which("docker") is None:
        return False, "docker is not installed or not on PATH"
    result = subprocess.run(
        ["docker", "exec", container, "sh", "-lc", f"command -v {shlex.quote(tool)}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    return result.returncode == 0, result.stdout.strip() or result.stderr.strip()


def search_exploit(args: dict) -> dict[str, Any]:
    query = " ".join(
        str(args.get(key) or "").strip() for key in ("product", "version", "service", "cve")
    ).strip()
    if not query:
        raise ValueError("provide product, version, service, or cve")
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
        raise RuntimeError(result.stderr.strip() or "searchsploit failed")
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("searchsploit returned malformed JSON") from exc
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
                "identifiers": [value for value in (args.get("cve"),) if value],
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
