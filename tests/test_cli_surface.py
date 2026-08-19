"""CLI surface stays aligned with the registered guard architecture."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "violin_guard.py"
SMOKE_SCRIPT = ROOT / "scripts" / "smoke-test.sh"


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
