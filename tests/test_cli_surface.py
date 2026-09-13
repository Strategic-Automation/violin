"""CLI surface stays aligned with the registered guard architecture."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.cli_environment import _format_command

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "violin_guard.py"
SMOKE_SCRIPT = ROOT / "scripts" / "smoke-test.sh"


@pytest.mark.parametrize("script_name", ["violin_guard.py", "generate-closeout.py"])
@pytest.mark.parametrize("missing_module", ["pydantic", "yaml", "plugins.violin_guard.registry"])
def test_cli_import_failure_diagnostic(script_name: str, missing_module: str) -> None:
    script = ROOT / "scripts" / script_name
    # Block imports even if virtualenv discovery adds another site-packages directory.
    runner = """
import importlib.abc
import runpy
import sys
from pathlib import Path

missing_module, script, *args = sys.argv[1:]

class MissingDependency(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == missing_module:
            raise ModuleNotFoundError(f"No module named '{fullname}'", name=fullname)

sys.meta_path.insert(0, MissingDependency())
sys.path.insert(0, str(Path(script).parent))
sys.argv = [script, *args]
runpy.run_path(script, run_name="__main__")
"""
    result = subprocess.run(
        [sys.executable, "-c", runner, missing_module, str(script), "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 1
    assert missing_module in result.stderr
    if missing_module.startswith("plugins."):
        assert "Traceback" in result.stderr
        assert "uv run" not in result.stderr
    else:
        assert "Traceback" not in result.stderr
        assert sys.executable in result.stderr
        assert (
            "'uv' 'run' '--project'" in result.stderr
            if sys.platform == "win32"
            else "uv run --project" in result.stderr
        )
        assert str(script) in result.stderr
        assert "--help" in result.stderr


@pytest.mark.parametrize("script_name", ["violin_guard.py", "generate-closeout.py"])
def test_cli_without_virtualenv_prints_copyable_command(tmp_path: Path, script_name: str) -> None:
    checkout = tmp_path / "checkout with spaces"
    for directory in ("scripts", "plugins"):
        shutil.copytree(
            ROOT / directory,
            checkout / directory,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    script = checkout / "scripts" / script_name
    args = ["--eng-dir", "engagement with spaces", "--target", "example.test"]
    result = subprocess.run(
        [sys.executable, "-S", str(script), *args],
        cwd=tmp_path,
        env={**os.environ, "VIRTUAL_ENV": str(tmp_path / "missing-venv"), "PYTHONPATH": ""},
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 1
    assert "pydantic" in result.stderr
    assert "Traceback" not in result.stderr
    assert sys.executable in result.stderr
    expected_arguments = [
        "uv",
        "run",
        "--project",
        str(checkout),
        "python",
        str(script),
        *args,
    ]
    command = result.stderr.splitlines()[-1].strip()
    if sys.platform == "win32":
        assert "Run in PowerShell" in result.stderr
        assert command == _format_command(expected_arguments, powershell=True)
    else:
        assert shlex.split(command) == expected_arguments


def test_recovery_command_quotes_powershell_arguments() -> None:
    arguments = ["uv", "run", "--project", r"C:\O'Brien\my project", "", "a&b", "$name"]
    assert _format_command(arguments, powershell=True) == (
        r"& 'uv' 'run' '--project' 'C:\O''Brien\my project' '' 'a&b' '$name'"
    )


def test_recovery_command_preserves_posix_arguments() -> None:
    arguments = ["uv", "run", "--project", "/O'Brien/my project", "", "a&b", "$name"]
    assert shlex.split(_format_command(arguments, powershell=False)) == arguments


def test_cli_does_not_advertise_removed_adapter_commands() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "search-exploit" not in result.stdout
    assert "adapters" not in SCRIPT.read_text(encoding="utf-8")


def test_smoke_script_imports_from_owning_modules() -> None:
    source = SMOKE_SCRIPT.read_text(encoding="utf-8")

    assert "from plugins.violin_guard import history" not in source
    assert "from plugins.violin_guard import history, service, state" not in source

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from plugins.violin_guard import handlers as service; "
                "from plugins.violin_guard.core import history, state; "
                "assert service and history and state"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_generate_closeout_script_surface() -> None:
    closeout_script = ROOT / "scripts" / "generate-closeout.py"
    assert closeout_script.is_file()

    result = subprocess.run(
        [sys.executable, str(closeout_script), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--eng-dir" in result.stdout
    assert "--target" in result.stdout
