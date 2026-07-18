from __future__ import annotations

from pathlib import Path

import pytest

from plugins.violin_guard import execution
from plugins.violin_guard.runtime_backend import resolve_backend


def test_auto_uses_native_kali_or_parrot(tmp_path: Path) -> None:
    resolution = resolve_backend(
        "auto", tmp_path, native_probe=lambda: True, docker_probe=lambda *_: (False, "unused")
    )
    assert resolution.resolved == "local"
    assert not resolution.fallback_reason


def test_auto_uses_valid_docker_container(tmp_path: Path) -> None:
    resolution = resolve_backend(
        "auto",
        tmp_path,
        native_probe=lambda: False,
        docker_probe=lambda *_: (True, "/engagements/x"),
    )
    assert resolution.resolved == "docker"
    assert resolution.mount == "/engagements/x"


def test_auto_falls_back_locally_with_a_reason(tmp_path: Path) -> None:
    resolution = resolve_backend(
        "auto",
        tmp_path,
        native_probe=lambda: False,
        docker_probe=lambda *_: (False, "docker missing"),
    )
    assert resolution.resolved == "local"
    assert resolution.fallback_reason == "docker missing"


def test_explicit_docker_fails_when_mount_is_invalid(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not mount"):
        resolve_backend(
            "docker", tmp_path, docker_probe=lambda *_: (False, "does not mount /engagements/x")
        )


def test_docker_command_uses_engagement_mount(tmp_path: Path, monkeypatch) -> None:
    eng = tmp_path / "assessment-a"
    eng.mkdir()
    monkeypatch.setattr(execution.shutil, "which", lambda _: "docker")
    argv = execution._command_argv("id", "docker", eng, eng, "kali-pentest")
    assert argv[:5] == ["docker", "exec", "-i", "-w", "/engagements/assessment-a"]
