"""Actionable dependency errors for the standalone diagnostic CLIs."""

from __future__ import annotations

import os
import shlex
import subprocess
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


def ensure_venv(profile_root: Path) -> None:
    """Re-exec inside the project venv when a runtime dependency is missing.

    Adds the venv's site-packages to sys.path when that is enough, and hands off to
    the venv interpreter when it is not. Deliberately exits the process on handoff:
    the child re-runs this file's caller with the original argv.
    """
    try:
        import pydantic  # noqa: F401

        return
    except ImportError:
        pass

    candidates: list[Path] = []
    if os.getenv("VIRTUAL_ENV"):
        candidates.append(Path(os.environ["VIRTUAL_ENV"]))
    candidates.extend(
        [
            profile_root / ".venv",
            profile_root.parent / ".venv",
            Path("/violin/.venv"),
        ]
    )

    for venv in candidates:
        if not venv.is_dir():
            continue
        site_packages = list(venv.glob("lib/python*/site-packages")) + list(
            venv.glob("Lib/site-packages")
        )
        for sp in site_packages:
            if sp.is_dir() and str(sp) not in sys.path:
                sys.path.insert(0, str(sp))
        try:
            import pydantic  # noqa: F401

            return
        except ImportError:
            pass

        for exe_name in ("bin/python", "bin/python3", "Scripts/python.exe", "Scripts/python"):
            exe = venv / exe_name
            if exe.is_file() and Path(sys.executable).resolve() != exe.resolve():
                res = subprocess.run([str(exe), *sys.argv], check=False)
                sys.exit(res.returncode)
