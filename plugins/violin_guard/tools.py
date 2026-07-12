"""JSON adapters for the Violin Guard Hermes plugin."""

from __future__ import annotations

from .core import service
from .core.adapters import build_ffuf, build_httpx, build_nmap, build_nuclei


def _call(fn, args, **kwargs):
    try:
        return fn(args or {}, **kwargs)
    except Exception as exc:
        return service._json("error", error=str(exc))


def handle_check_command(args, **kwargs):
    return _call(service.handle_check_command, args)


def handle_record_ptt(args, **kwargs):
    return _call(service.handle_record_ptt, args)


def handle_record_hypothesis(args, **kwargs):
    return _call(service.handle_record_hypothesis, args)


def handle_exec(args, **kwargs):
    return _call(service.handle_exec, args)


def handle_exec_status(args, **kwargs):
    return _call(service.handle_exec_status, args)


def handle_exec_cancel(args, **kwargs):
    return _call(service.handle_exec_cancel, args)


def handle_sync_done(args, **kwargs):
    return _call(service.handle_sync_done, args)


def handle_heartbeat_done(args, **kwargs):
    return _call(service.handle_heartbeat_done, args)


def handle_exec_burst(args, **kwargs):
    return _call(service.handle_exec_burst, args)


def handle_target(args, **kwargs):
    return _call(service.handle_target, args)


def handle_status(args, **kwargs):
    return _call(service.handle_status, args)


def handle_search_exploit(args, **kwargs):
    return _call(service.handle_search_exploit, args)


def _adapter(builder):
    return lambda args, **kwargs: _call(
        service.handle_exec, {**(args or {}), "command": builder(args or {})}
    )


handle_nmap = _adapter(build_nmap)
handle_httpx = _adapter(build_httpx)
handle_nuclei = _adapter(build_nuclei)
handle_ffuf = _adapter(build_ffuf)

__all__ = [name for name in globals() if name.startswith("handle_")]
