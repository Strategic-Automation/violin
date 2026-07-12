"""JSON adapters for the Violin Guard Hermes plugin."""
from __future__ import annotations
from .core import service
from .core.adapters import build_ffuf, build_httpx, build_nmap, build_nuclei, search_exploit

def _call(fn, args, **kwargs):
    try:
        return fn(args or {}, **kwargs)
    except Exception as exc:
        return service._json("error", error=str(exc))

handle_check_command = lambda args, **kwargs: _call(service.handle_check_command, args)
handle_record_ptt = lambda args, **kwargs: _call(service.handle_record_ptt, args)
handle_record_hypothesis = lambda args, **kwargs: _call(service.handle_record_hypothesis, args)
handle_exec = lambda args, **kwargs: _call(service.handle_exec, args)
handle_exec_status = lambda args, **kwargs: _call(service.handle_exec_status, args)
handle_exec_cancel = lambda args, **kwargs: _call(service.handle_exec_cancel, args)
handle_sync_done = lambda args, **kwargs: _call(service.handle_sync_done, args)
handle_heartbeat_done = lambda args, **kwargs: _call(service.handle_heartbeat_done, args)
handle_exec_burst = lambda args, **kwargs: _call(service.handle_exec_burst, args)
handle_target = lambda args, **kwargs: _call(service.handle_target, args)
handle_status = lambda args, **kwargs: _call(service.handle_status, args)
handle_search_exploit = lambda args, **kwargs: _call(service.handle_search_exploit, args)

def _adapter(builder):
    return lambda args, **kwargs: _call(service.handle_exec, {**(args or {}), "command": builder(args or {})})
handle_nmap = _adapter(build_nmap)
handle_httpx = _adapter(build_httpx)
handle_nuclei = _adapter(build_nuclei)
handle_ffuf = _adapter(build_ffuf)

__all__ = [name for name in globals() if name.startswith("handle_")]
