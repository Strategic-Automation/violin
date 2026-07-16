"""JSON adapters for the Violin Guard Hermes plugin."""

from __future__ import annotations

import shlex

from .core import service
from .core.adapters import (
    build_ffuf,
    build_httpx,
    build_netcat_listener,
    build_nmap,
    build_nuclei,
)


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


def handle_rebind_pending_batch(args, **kwargs):
    return _call(service.handle_rebind_pending_batch, args)


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
    def execute_adapter(args, **kwargs):
        values = args or {}
        built = builder(values)
        return _call(
            service.handle_exec,
            {
                **values,
                "target": values.get("target") or values.get("url"),
                "command": built,
                # Safe here because adapter builders quote every controlled
                # value; raw violin_exec commands continue through the shell.
                "_argv": shlex.split(built, posix=True),
            },
        )

    return execute_adapter


handle_nmap = _adapter(build_nmap)
handle_httpx = _adapter(build_httpx)
handle_nuclei = _adapter(build_nuclei)
handle_ffuf = _adapter(build_ffuf)


def handle_listener(args, **kwargs):
    values = args or {}
    built = build_netcat_listener(values)
    return _call(
        service.handle_exec,
        {
            **values,
            "command": built,
            "_argv": shlex.split(built, posix=True),
            "background": True,
        },
    )


__all__ = [name for name in globals() if name.startswith("handle_")]
