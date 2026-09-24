"""Runtime selection for native Kali/Parrot, Docker Kali, and local fallback."""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackendResolution:
    requested: str
    resolved: str
    platform: str
    container: str = ""
    mount: str = ""
    fallback_reason: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _native_kali_or_parrot(os_release: Path = Path("/etc/os-release")) -> bool:
    if platform.system().lower() != "linux" or not os_release.is_file():
        return False
    text = os_release.read_text(encoding="utf-8", errors="replace").lower()
    return "id=kali" in text or "id=parrot" in text or "kali linux" in text or "parrot os" in text


def _docker_container_ready(
    container: str, engagement: Path, run: Callable = subprocess.run
) -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker executable not found"
    try:
        result = run(
            ["docker", "inspect", "--format", "{{.State.Running}}|{{json .Mounts}}", container],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"Docker container {container!r} probe timed out"
    if result.returncode != 0:
        return False, f"Docker container {container!r} is unavailable"
    running, _, mounts = result.stdout.strip().partition("|")
    expected = f"/engagements/{engagement.name}"
    if running.strip().lower() != "true":
        return False, f"Docker container {container!r} is not running"
    if expected not in mounts:
        return False, f"Docker container {container!r} does not mount {expected}"
    return True, expected


def resolve_backend(
    requested: str,
    engagement: Path,
    *,
    container: str = "kali-pentest",
    docker_probe: Callable = _docker_container_ready,
    native_probe: Callable = _native_kali_or_parrot,
    cache_ttl: float = 5.0,
) -> BackendResolution:
    """Resolve a backend without installing packages or starting containers.

    The docker/native probes are memoized for a short ``cache_ttl`` because they
    spawn subprocesses on every call; stale results are bounded by the TTL so a
    container starting/stopping mid-session is still picked up after the window.
    """
    choice = str(requested or "auto").strip().lower()
    if choice not in {"auto", "local", "docker"}:
        raise ValueError("backend must be auto, local, or docker")
    host = platform.system().lower()
    if choice == "local":
        return BackendResolution(choice, "local", host)
    if choice == "docker":
        ready, detail = _cached_docker_probe(docker_probe, container, engagement, cache_ttl)
        if not ready:
            raise ValueError(f"Docker backend unavailable: {detail}")
        return BackendResolution(choice, "docker", host, container, detail)
    if native_probe():
        return BackendResolution(choice, "local", host)
    ready, detail = _cached_docker_probe(docker_probe, container, engagement, cache_ttl)
    if ready:
        return BackendResolution(choice, "docker", host, container, detail)
    return BackendResolution(choice, "local", host, fallback_reason=detail)


def _cached_docker_probe(
    probe: Callable,
    container: str,
    engagement: Path,
    ttl: float,
) -> tuple[bool, str]:
    """Run the docker probe at most once per ``ttl`` per (probe, container, eng)."""
    now = time.monotonic()
    key = (id(probe), container, str(engagement.resolve()))
    entry = _BACKEND_CACHE.get(key)
    if entry is not None and (now - entry[0]) < ttl:
        return entry[1]
    result = probe(container, engagement)
    _BACKEND_CACHE[key] = (now, result)
    return result


_BACKEND_CACHE: dict[tuple[int, str, str], tuple[float, tuple[bool, str]]] = {}


def runtime_readiness(engagement: Path) -> dict[str, object]:
    resolution = resolve_backend("auto", engagement)
    return {
        "native_kali_or_parrot": _native_kali_or_parrot(),
        "docker_executable": bool(shutil.which("docker")),
        "auto": resolution.to_dict(),
    }
