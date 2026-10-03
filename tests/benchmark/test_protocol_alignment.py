from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from benchmark.score import _protocol_alignment, load_golden_manifest


@pytest.mark.parametrize(
    ("target", "identity", "expected"),
    [
        (
            "https://duck-store.escape.tech",
            "escape-duck-store-online:2026-09-27T18:00:17Z",
            False,
        ),
        (
            "https://duck-store.escape.tech",
            "escape-duck-store-2026-04:sha256:" + "a" * 64,
            False,
        ),
        (
            "http://localhost:8080",
            "escape-duck-store-online:2026-09-27T18:00:17Z",
            False,
        ),
        (
            "http://localhost:8080",
            "escape-duck-store-2026-04:sha256:" + "a" * 64,
            True,
        ),
        ("http://[invalid", "escape-duck-store-2026-04:reset-42", False),
    ],
)
def test_protocol_requires_isolated_duck_store_identity(
    tmp_path: Path, target: str, identity: str, expected: bool
) -> None:
    (tmp_path / "scope").mkdir()
    (tmp_path / "run-manifest.json").write_text(
        json.dumps(
            {
                "target": target,
                "target_isolation": {"declared": True, "snapshot_or_reset_id": identity},
                "source": {"git_commit": "a" * 40, "git_dirty": False},
                "runtime": {"image_digest": "sha256:" + "a" * 64},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "scope" / "scope.yaml").write_text(
        yaml.safe_dump(
            {
                "engagement": {
                    "brief": "Use /openapi.json with admin / admin and user / password."
                },
                "benchmark": {"openapi_spec": "http://localhost:8080/openapi.json"},
                "exclusions": {"paths": []},
                "rules_of_engagement": {"forbidden_actions": ["read source code"]},
            }
        ),
        encoding="utf-8",
    )
    golden = load_golden_manifest()

    result = _protocol_alignment(
        tmp_path,
        contract={**golden["contract"], "target": golden["target"]},
        trusted_fixture=False,
    )

    assert result["checks"]["target_isolation_declared"] is expected
    assert result["comparable"] is expected
    assert result["reproducible"] is expected
