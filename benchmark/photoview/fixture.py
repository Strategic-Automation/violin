"""Provision and run disposable local fixtures, never assessment probes."""

from __future__ import annotations

import argparse
import json
import secrets
import struct
import subprocess
import tarfile
import time
import uuid
import zlib
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

from benchmark.photoview import PROTOCOL, SOURCE_COMMIT
from benchmark.photoview.run import source_digest
from benchmark.run import _PROVIDER_KEY_ENV

TARGET_IMAGE = (
    "viktorstrate/photoview@sha256:f914c44b202fc8175e09bd56f35bb1a4a7c04dc451652306f240aabc3eea133e"
)
DATABASE_IMAGE = "mariadb@sha256:7db29378d4fdab73f8123bbc2b48905c90d1a4b00cf848b028f1e81e623257f2"


def media_ready(media: list[dict]) -> bool:
    """Require processed image URLs, not only database media rows."""
    return bool(media) and all(
        row.get("thumbnail")
        and row["thumbnail"].get("url")
        and row.get("highRes")
        and row["highRes"].get("url")
        for row in media
    )


def command(*args: str, capture: bool = False) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else ""


def png(red: int, green: int, blue: int) -> bytes:
    """A deterministic synthetic photo, generated without another dependency."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    raw = (b"\0" + bytes([red, green, blue]) * 32) * 32
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def graphql(port: int, query: str, variables: dict | None = None, token: str = "") -> dict:
    """Administrative fixture initialization only; never used by the assessment."""
    request = Request(
        f"http://127.0.0.1:{port}/api/graphql",
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={
            "Content-Type": "application/json",
            **({"Cookie": f"auth-token={token}"} if token else {}),
        },
    )
    with urlopen(request, timeout=20) as response:
        value = json.load(response)
    if value.get("errors"):
        raise ValueError(f"fixture GraphQL error: {value['errors']}")
    return value["data"]


def compose(directory: Path, *args: str) -> None:
    metadata = json.loads((directory / "fixture.json").read_text(encoding="utf-8"))
    project = metadata["project"]
    if not project.startswith("violin-pv-") or not project.removeprefix("violin-pv-").isalnum():
        raise ValueError("invalid disposable fixture project")
    command(
        "docker",
        "compose",
        "--progress",
        "quiet",
        "-p",
        project,
        "-f",
        str(directory / "compose.yaml"),
        *args,
    )


def compose_config(directory: Path, port: int, database_root_password: str) -> dict:
    return {
        "services": {
            "photoview": {
                "image": TARGET_IMAGE,
                "ports": [f"127.0.0.1:{port}:80"],
                "depends_on": {
                    "database": {"condition": "service_healthy"},
                    "cache-init": {"condition": "service_completed_successfully"},
                },
                "environment": {
                    "PHOTOVIEW_DATABASE_DRIVER": "mysql",
                    "PHOTOVIEW_MYSQL_URL": "photoview:fixture-only@tcp(database)/photoview",
                    "PHOTOVIEW_LISTEN_IP": "0.0.0.0",
                    "PHOTOVIEW_LISTEN_PORT": "80",
                },
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(directory / "media"),
                        "target": "/photos",
                        "read_only": True,
                    },
                    "cache:/home/photoview/media-cache",
                ],
            },
            "cache-init": {
                "image": TARGET_IMAGE,
                "user": "0:0",
                "entrypoint": ["/bin/sh", "-c"],
                "command": ["chown -R 999:999 /cache"],
                "volumes": ["cache:/cache"],
            },
            "database": {
                "image": DATABASE_IMAGE,
                "environment": {
                    "MARIADB_DATABASE": "photoview",
                    "MARIADB_USER": "photoview",
                    "MARIADB_PASSWORD": "fixture-only",
                    "MARIADB_ROOT_PASSWORD": database_root_password,
                },
                "volumes": ["database:/var/lib/mysql"],
                "healthcheck": {
                    "test": ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 60,
                },
            },
        },
        "volumes": {"database": {}, "cache": {}},
    }


def setup(directory: Path, port: int) -> dict:
    if not 1024 <= port <= 65535:
        raise ValueError("fixture port must be between 1024 and 65535")
    directory.mkdir(parents=True, exist_ok=False)
    checkout = directory / "checkout"
    command(
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        "v2.4.0",
        "https://github.com/photoview/photoview.git",
        str(checkout),
    )
    actual = command("git", "-C", str(checkout), "rev-parse", "HEAD", capture=True)
    if actual != SOURCE_COMMIT:
        raise ValueError("Photoview tag no longer matches the pinned source commit")
    archive = directory / "source.tar"
    command(
        "git",
        "-C",
        str(checkout),
        "archive",
        "--format=tar",
        "--output",
        str(archive),
        SOURCE_COMMIT,
    )
    source = directory / "source"
    source.mkdir()
    with tarfile.open(archive) as handle:
        handle.extractall(source, filter="data")
    project = "violin-pv-" + uuid.uuid4().hex[:12]
    metadata = {
        "protocol": PROTOCOL,
        "project": project,
        "fixture_id": uuid.uuid4().hex,
        "created_at": datetime.now(UTC).isoformat(),
        "port": port,
        "source_commit": SOURCE_COMMIT,
        "source_sha256": source_digest(source),
        "target_image": TARGET_IMAGE,
        "database_image": DATABASE_IMAGE,
        "dataset": "synthetic-png-v1",
        "consumed": False,
        "ready": False,
    }
    (directory / "fixture.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    for name, color in (("admin", (210, 30, 40)), ("user", (30, 80, 210))):
        album = directory / "media" / name / "album"
        album.mkdir(parents=True)
        (album / f"{name}.png").write_bytes(png(*color))
    config = compose_config(directory, port, secrets.token_urlsafe(24))
    (directory / "compose.yaml").write_text(
        yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
    )
    compose(directory, "up", "-d", "--wait", "--wait-timeout", "180")
    image = json.loads(command("docker", "image", "inspect", TARGET_IMAGE, capture=True))[0]
    if image["Config"]["Labels"].get("org.opencontainers.image.revision") != SOURCE_COMMIT:
        raise ValueError("target image does not match the supplied source")
    metadata["target_image_id"] = image["Id"]
    metadata["database_image_id"] = command(
        "docker", "image", "inspect", DATABASE_IMAGE, "--format", "{{.Id}}", capture=True
    )
    for attempt in range(60):
        try:
            graphql(port, "{ siteInfo { initialSetup } }")
            break
        except (URLError, TimeoutError):
            if attempt == 59:
                raise
            time.sleep(1)
    result = graphql(
        port,
        """
        mutation { initialSetupWizard(username:"admin", password:"PhotoviewAdmin!2026",
        rootPath:"/photos/admin") { success token } }
    """,
    )["initialSetupWizard"]
    if not result or not result["success"] or not result.get("token"):
        raise ValueError("fixture admin setup failed")
    token = result["token"]
    ordinary_password = secrets.token_urlsafe(24)
    ordinary = graphql(
        port,
        """
        mutation($password:String!) { createUser(username:"user", password:$password, admin:false) { id } }
    """,
        {"password": ordinary_password},
        token,
    )["createUser"]
    graphql(
        port,
        """
        mutation($id:ID!) { userAddRootPath(id:$id, rootPath:"/photos/user") { id } }
    """,
        {"id": ordinary["id"]},
        token,
    )
    scan = graphql(port, "mutation { scanAll { success finished } }", token=token)["scanAll"]
    if not scan["success"]:
        raise ValueError("fixture media scan failed")
    ordinary_auth = graphql(
        port,
        'mutation($password:String!) { authorizeUser(username:"user", password:$password) { success token } }',
        {"password": ordinary_password},
    )["authorizeUser"]
    if not ordinary_auth["success"]:
        raise ValueError("ordinary fixture account cannot authenticate")
    media_counts = []
    for principal_token in (token, ordinary_auth["token"]):
        for attempt in range(180):
            media = graphql(
                port,
                "{ myMedia { id thumbnail { url } highRes { url } } }",
                token=principal_token,
            )["myMedia"]
            if media_ready(media):
                media_counts.append(len(media))
                break
            if attempt == 179:
                raise ValueError(
                    "fixture scan did not produce thumbnail and high-resolution URLs for both principals"
                )
            time.sleep(1)
    metadata["media_counts"] = media_counts
    metadata["media_readiness"] = "thumbnail-and-high-resolution-urls-for-each-principal"
    metadata.update(ready=True, seed={"accounts": 2, "admin": "admin", "ordinary": "user"})
    (directory / "fixture.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def run(
    directory: Path,
    output: Path,
    runtime_image: str,
    model: str,
    provider: str,
    api_base: str,
    dry_run: bool = False,
) -> int:
    metadata_path = directory / "fixture.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (
        metadata.get("protocol") != PROTOCOL
        or not metadata.get("ready")
        or metadata.get("consumed")
    ):
        raise ValueError("use a fresh, fully seeded Photoview fixture for each independent run")
    source = directory / "source"
    if source_digest(source) != metadata["source_sha256"]:
        raise ValueError("source snapshot changed after fixture creation")
    image = command(
        "docker", "image", "inspect", runtime_image, "--format", "{{.Id}}", capture=True
    )
    output.mkdir(parents=True, exist_ok=False)
    revision = command("git", "rev-parse", "HEAD", capture=True)
    dirty = bool(command("git", "status", "--porcelain", capture=True))
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        metadata["project"] + "_default",
        "--mount",
        f"type=bind,source={source},target=/target-source,readonly",
        "--mount",
        f"type=bind,source={output},target=/violin/engagements",
        "--env",
        f"VIOLIN_SOURCE_COMMIT={revision}",
        "--env",
        f"VIOLIN_SOURCE_DIRTY={str(dirty).lower()}",
    ]
    key_env = _PROVIDER_KEY_ENV.get(provider.casefold())
    if key_env:
        cmd.extend(["--env", key_env])
    elif api_base:
        cmd.extend(["--env", "OPENAI_API_KEY"])
    cmd += [
        image,
        "uv",
        "run",
        "--no-dev",
        "python",
        "-m",
        "benchmark.photoview.run",
        "--eng-dir",
        "/violin/engagements/run",
        "--fixture-id",
        metadata["fixture_id"],
        "--target-image",
        metadata["target_image_id"],
        "--database-image",
        metadata["database_image_id"],
        "--runtime-image",
        image,
        "--model",
        model,
        "--provider",
        provider,
    ]
    if api_base:
        cmd += ["--api-base", api_base]
    if dry_run:
        cmd.append("--dry-run")
    else:
        metadata["consumed"] = True
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return subprocess.run(cmd, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("setup")
    create.add_argument("--directory", type=Path, required=True)
    create.add_argument("--port", type=int, default=4800)
    execute = commands.add_parser("run")
    execute.add_argument("--directory", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--runtime-image", required=True)
    execute.add_argument("--model", required=True)
    execute.add_argument("--provider", required=True)
    execute.add_argument("--api-base", default="")
    execute.add_argument("--dry-run", action="store_true")
    destroy = commands.add_parser("down")
    destroy.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    directory = args.directory.resolve()
    if args.action == "setup":
        print(json.dumps(setup(directory, args.port), indent=2))
    elif args.action == "down":
        compose(directory, "down", "--volumes", "--remove-orphans")
    else:
        return run(
            directory,
            args.output.resolve(),
            args.runtime_image,
            args.model,
            args.provider,
            args.api_base,
            args.dry_run,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
