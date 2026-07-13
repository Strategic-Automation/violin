"""Violin guard — core subpackage with the shared state machine, execution, and adapters.

All modules in this package define their public API in ``__all__`` and are
importable directly from the installed plugin directory.
"""

from __future__ import annotations

from . import (
    adapters,
    bootstrap,
    command,
    execution,
    hypotheses,
    phases,
    ptt,
    release,
    service,
    state,
)

__all__ = [
    "adapters",
    "bootstrap",
    "command",
    "execution",
    "hypotheses",
    "phases",
    "ptt",
    "release",
    "service",
    "state",
]
