"""Actionable dependency errors for the standalone diagnostic CLIs."""

from __future__ import annotations

import shlex
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Import names for the runtime dependencies declared in pyproject.toml.
_DEPENDENCY_MODULES = {
    "bashlex",
    "cryptography",
    "duckduckgo_search",
    "filelock",
    "netaddr",
    "psutil",
    "pydantic",
    "tirith",
    "yaml",
    "yarl",
}


def _format_command(arguments: list[str], *, powershell: bool) -> str:
    if powershell:
        # PowerShell single-quoted strings are literal; apostrophes are doubled.
        return "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in arguments)
    return shlex.join(arguments)


@contextmanager
def project_imports(profile_root: Path) -> Iterator[None]:
    """Explain dependency failures without hiding internal project import errors."""
    try:
        yield
    except ImportError as exc:
        if not exc.name or exc.name.split(".")[0] not in _DEPENDENCY_MODULES:
            raise
        powershell = sys.platform == "win32"
        command = _format_command(
            [
                "uv",
                "run",
                "--project",
                str(profile_root),
                "python",
                str(Path(sys.argv[0]).resolve()),
                *sys.argv[1:],
            ],
            powershell=powershell,
        )
        shell_hint = " in PowerShell" if powershell else ""
        raise SystemExit(
            f"Cannot import a Violin dependency: {exc}\n"
            f"Current interpreter: {sys.executable}\n"
            f"Run{shell_hint} with the project environment instead:\n  {command}"
        ) from None
