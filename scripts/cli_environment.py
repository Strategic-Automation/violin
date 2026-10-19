"""Actionable dependency errors for the standalone diagnostic CLIs."""

from __future__ import annotations

import os
import shlex
import shutil
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

# Import names for the runtime dependencies declared in pyproject.toml.
_DEPENDENCY_MODULES = {
    "bashlex",
    "cryptography",
    "duckduckgo_search",
    "filelock",
    "markdown_it",
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


def _uv_command() -> str:
    """Find uv even when Hermes gives the tool shell a profile-local HOME/PATH."""
    executable = shutil.which("uv")
    if executable:
        return executable

    # Hermes can set HOME to <profile>/home. Walk back to the real account home
    # so uv installed by its standard installer remains discoverable.
    if sys.platform != "win32":
        home = Path.home()
        for directory in (home, *home.parents):
            for candidate in (
                directory / ".local" / "bin" / "uv",
                directory / ".cargo" / "bin" / "uv",
            ):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
    return "uv"


def _dependency_exit(profile_root: Path, headline: str) -> NoReturn:
    powershell = sys.platform == "win32"
    uv = _uv_command()
    command = _format_command(
        [
            uv,
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
    uv_hint = (
        "\nInstall uv or add its install directory to PATH before retrying." if uv == "uv" else ""
    )
    raise SystemExit(
        f"{headline}\n"
        f"Current interpreter: {sys.executable}\n"
        f"Run{shell_hint} with the project environment instead:\n  {command}{uv_hint}"
    )


@contextmanager
def project_imports(profile_root: Path) -> Iterator[None]:
    """Explain dependency failures without hiding internal project import errors."""
    try:
        yield
    except ImportError as exc:
        if not exc.name or exc.name.split(".")[0] not in _DEPENDENCY_MODULES:
            raise
        _dependency_exit(profile_root, f"Cannot import a Violin dependency: {exc}")


def ensure_venv(profile_root: Path) -> None:
    """Report the owning project's environment command when dependencies are absent."""
    try:
        import pydantic  # noqa: F401

        return
    except ImportError as exc:
        _dependency_exit(
            profile_root,
            f"Cannot import Violin runtime dependency {exc.name!r}.",
        )


@contextmanager
def cli_imports() -> Iterator[None]:
    """Prepare the checkout and venv, retaining actionable import diagnostics."""
    profile_root = Path(__file__).resolve().parent.parent
    if str(profile_root) not in sys.path:
        sys.path.insert(0, str(profile_root))
    with project_imports(profile_root):
        ensure_venv(profile_root)
        yield
