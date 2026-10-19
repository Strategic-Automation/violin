"""CLI surface stays aligned with the registered guard architecture."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from scripts.cli_environment import _DEPENDENCY_MODULES, _format_command, _uv_command

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "violin_guard.py"


def test_cli_dependency_modules_match_project_dependencies() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    import_aliases = {"pyyaml": "yaml", "markdown-it-py": "markdown_it"}
    expected_modules = set()
    for dependency in project["dependencies"]:
        package_name = canonicalize_name(Requirement(dependency).name)
        expected_modules.add(import_aliases.get(package_name, package_name.replace("-", "_")))

    assert expected_modules == _DEPENDENCY_MODULES


def test_readme_documents_native_cli_environment_setup() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "uv python install 3.11" in readme
    assert 'uv sync --project "$HOME/.hermes/profiles/violin" --no-dev' in readme
    assert "profile-local `HOME`" in readme


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
            _format_command([_uv_command(), "run", "--project"], powershell=True) in result.stderr
            if sys.platform == "win32"
            else shlex.join([_uv_command(), "run", "--project"]) in result.stderr
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
        _uv_command(),
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


def test_uv_recovery_finds_installer_path_above_hermes_profile_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    account_home = tmp_path / "account"
    profile_home = account_home / ".hermes" / "profiles" / "violin" / "home"
    uv = account_home / ".local" / "bin" / "uv"
    uv.parent.mkdir(parents=True)
    uv.touch()
    uv.chmod(0o755)
    profile_home.mkdir(parents=True)

    monkeypatch.setattr(Path, "home", staticmethod(lambda: profile_home))
    monkeypatch.setattr("scripts.cli_environment.shutil.which", lambda _: None)
    monkeypatch.setattr("scripts.cli_environment.sys.platform", "linux")

    assert _uv_command() == str(uv)


def test_missing_uv_diagnostic_explains_path_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins

    from scripts.cli_environment import ensure_venv

    original_import = builtins.__import__

    def missing_pydantic(name, *args, **kwargs):
        if name == "pydantic":
            raise ModuleNotFoundError("No module named 'pydantic'", name=name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_pydantic)
    monkeypatch.setattr("scripts.cli_environment.shutil.which", lambda _: None)
    monkeypatch.setattr("scripts.cli_environment.sys.platform", "win32")

    with pytest.raises(SystemExit, match="Install uv or add its install directory to PATH"):
        ensure_venv(ROOT)


def test_cli_does_not_advertise_removed_adapter_commands() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "search-exploit" not in result.stdout
    assert "exec-burst" not in result.stdout
    assert "adapters" not in SCRIPT.read_text(encoding="utf-8")


def test_guard_imports_from_owning_modules() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from plugins.violin_guard import handlers as service; "
                "from plugins.violin_guard.core.engagement import state; "
                "from plugins.violin_guard.core.evidence import history; "
                "assert service and history and state"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_generate_closeout_script_surface(tmp_path: Path) -> None:
    closeout_script = ROOT / "scripts" / "generate-closeout.py"
    assert closeout_script.is_file()

    result = subprocess.run(
        [sys.executable, str(closeout_script), "--help"],
        cwd=tmp_path,
        env={**os.environ, "PATH": ""},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--eng-dir" in result.stdout
    assert "--target" in result.stdout


def test_cli_entry_points_share_one_venv_bootstrap() -> None:
    """Venv discovery lives in cli_environment, not in each entry point."""
    environment = (ROOT / "scripts" / "cli_environment.py").read_text(encoding="utf-8")
    assert "def ensure_venv(" in environment

    for name in ("violin_guard.py", "generate-closeout.py"):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "cli_imports" in source, f"{name} does not use the shared bootstrap"
        assert "def _ensure_venv" not in source, f"{name} still carries its own copy"
        assert "site-packages" not in source, f"{name} still walks site-packages itself"


@pytest.mark.parametrize("module", ["scripts.violin_guard", "scripts.generate-closeout"])
def test_cli_module_entry_points(module):
    result = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def test_project_imports_diagnostic_message(tmp_path: Path) -> None:
    from scripts.cli_environment import project_imports

    with pytest.raises(SystemExit) as exc_info, project_imports(tmp_path):
        raise ImportError("No module named 'yaml'", name="yaml")

    message = str(exc_info.value)
    assert message.startswith("Cannot import a Violin dependency: No module named 'yaml'\n")
    assert f"Current interpreter: {sys.executable}\n" in message
    assert "with the project environment instead:\n" in message


def test_ensure_venv_diagnostic_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    from scripts.cli_environment import ensure_venv

    orig_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "pydantic":
            raise ModuleNotFoundError("No module named 'pydantic'", name="pydantic")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    with pytest.raises(SystemExit) as exc_info:
        ensure_venv(tmp_path)

    message = str(exc_info.value)
    assert message.startswith("Cannot import Violin runtime dependency 'pydantic'.\n")
    assert f"Current interpreter: {sys.executable}\n" in message
    assert "with the project environment instead:\n" in message
