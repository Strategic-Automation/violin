import os
import shlex
import sys
from pathlib import Path

from ..adapters import (
    AdapterError,
    build_ffuf,
    build_httpx,
    build_netcat_listener,
    build_nuclei,
    resolve_ffuf_wordlist,
    search_exploit,
)
from . import exec_handlers
from .base import _call, _eng_path, _json, _serialise_errors


def _get_handle_exec():
    handlers_mod = sys.modules.get("plugins.violin_guard.handlers")
    if handlers_mod and hasattr(handlers_mod, "handle_exec"):
        return handlers_mod.handle_exec
    return exec_handlers.handle_exec


def _adapter(builder):
    """Create a handler that builds a command via ``builder`` then passes it to handle_exec."""

    def execute_adapter(args, **kwargs):
        values = args or {}
        built = builder(values)
        return _call(
            _get_handle_exec(),
            {
                **values,
                "target": values.get("target") or values.get("url"),
                "command": built,
            },
            _internal_argv=shlex.split(built, posix=True),
        )

    return execute_adapter


handle_httpx = _adapter(build_httpx)
handle_nuclei = _adapter(build_nuclei)


@_serialise_errors
def handle_ffuf(args, **kwargs):
    """Resolve a portable wordlist before dispatching the typed ffuf command."""

    values = dict(args or {})
    try:
        orig_eng_dir = os.environ.get("ENG_DIR")
        if values.get("eng_dir"):
            os.environ["ENG_DIR"] = str(values["eng_dir"])
        try:
            values["wordlist"] = resolve_ffuf_wordlist(values.get("wordlist"))
        finally:
            if orig_eng_dir is None:
                os.environ.pop("ENG_DIR", None)
            else:
                os.environ["ENG_DIR"] = orig_eng_dir
        token_file = str(values.get("auth_token_file") or "").strip()
        if token_file:
            engagement = _eng_path(str(values.get("eng_dir") or ""))
            path = Path(token_file)
            if not path.is_absolute():
                path = engagement / path
            path = path.resolve()
            evidence_root = (engagement / "evidence").resolve()
            if evidence_root not in path.parents:
                raise AdapterError(
                    "auth_token_file must be inside the engagement evidence directory"
                )
            token = path.read_text(encoding="utf-8").strip()
            if not token:
                raise AdapterError("auth_token_file is empty")
            values["headers"] = [
                *(values.get("headers") or []),
                f"Authorization: Bearer {token}",
            ]
    except AdapterError as exc:
        return _json("error", executed=False, error=str(exc))
    built = build_ffuf(values)
    return _call(
        _get_handle_exec(),
        {
            **values,
            "target": values.get("target") or values.get("url"),
            "command": built,
        },
        _internal_argv=shlex.split(built, posix=True),
    )


@_serialise_errors
def handle_search_exploit(a, **kwargs):
    return _json("ok", **search_exploit(a))


def _listener_scope_check(eng_dir: str, scope: str, bind_host: str, values: dict) -> dict:
    """Gate a local catch listener."""
    from ..targets import _callback_hosts, normalise_target, scope_hosts

    canonical_scope = (_eng_path(eng_dir) / "scope" / "scope.yaml").resolve()
    requested_scope = Path(scope).expanduser().resolve() if scope else canonical_scope
    if requested_scope != canonical_scope:
        return _json(
            "blocked",
            error="runtime adapter execution must use the engagement's canonical scope.yaml",
        )

    host = (bind_host or "").strip()
    host_norm = host
    if host:
        if host.startswith("[") and "]" in host:
            host_norm = host.split("]")[0].lstrip("[")
        elif host.count(":") == 1:
            host_norm = host.split(":")[0].strip()
    if not host or host_norm in {"0.0.0.0", "::", "127.0.0.1", "::1", "localhost"}:
        return {}
    scope_path = canonical_scope
    if not scope_path.exists():
        return {}
    try:
        import yaml

        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    allowed = {h.lower() for h in scope_hosts(data, "targets")}
    callbacks = {h.lower() for h in _callback_hosts(data)}
    norm = normalise_target(host_norm).lower()
    if norm in allowed and norm not in callbacks:
        return {
            "error": (
                f"listener bind_host {host!r} is an in-scope target address; a listener "
                "must bind the attacker's own interface (omit bind_host, use 0.0.0.0, "
                "or a declared assessment_hosts.callback_hosts entry), not the target"
            )
        }
    return {}


@_serialise_errors
def handle_listener(args, **kwargs):
    values = args or {}
    scoped = _listener_scope_check(
        str(values.get("eng_dir", "")),
        str(values.get("scope", "") or ""),
        str(values.get("bind_host", "") or ""),
        values,
    )
    if scoped.get("error"):
        return _json("blocked", executed=False, error=scoped["error"])
    built = build_netcat_listener(values)
    return _call(
        _get_handle_exec(),
        {
            **values,
            "command": built,
        },
        _internal_argv=shlex.split(built, posix=True),
        _internal_background=True,
    )
