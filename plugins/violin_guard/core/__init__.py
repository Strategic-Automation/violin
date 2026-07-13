"""Violin guard — core subpackage with the shared state machine, execution, and adapters.

All modules in this package define their public API in ``__all__``. Functions that
depend on the ``scripts/guard/`` package use lazy imports inside their bodies so
the module graph is resolvable without ``scripts/`` on ``sys.path`` at import time.
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
