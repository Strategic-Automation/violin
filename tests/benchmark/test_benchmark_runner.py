"""Contract tests for benchmark runner behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.run import (
    _hermes_environment,
    _run_manifest,
    _scope_for_target,
    init_benchmark_engagement,
    parse_args,
)


def test_agent_scope_contains_routes_but_no_evaluator_identity() -> None:
    scope = _scope_for_target("https://duck-store.escape.tech")
    serialized = json.dumps(scope).casefold()
    assert "post /api/v1/auth/login" in serialized
    assert scope["benchmark"]["openapi_spec"].endswith("/openapi.json")
    assert "/openapi.json" not in scope["exclusions"]["paths"]
    assert "/vulnerabilities" in scope["exclusions"]["paths"]
    assert "challenge" not in serialized
    assert "golden" not in serialized


def test_benchmark_runner_does_not_select_model_or_provider_defaults() -> None:
    args = parse_args([])
    assert args.model == ""
    assert args.provider == ""
    assert args.api_base == ""


def test_run_manifest_uses_explicit_source_metadata_without_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("benchmark.run._git_output", lambda *_args: "unknown")
    monkeypatch.setenv("VIOLIN_SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv("VIOLIN_SOURCE_DIRTY", "false")
    manifest = _run_manifest(
        parse_args(["--target", "https://example.test"]),
        tmp_path / "run-1",
        public_key=b"public",
        started_at="2026-09-25T00:00:00+00:00",
    )
    assert manifest["source"]["git_commit"] == "a" * 40
    assert manifest["source"]["git_dirty"] is False


def test_run_manifest_fails_closed_when_source_metadata_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("benchmark.run._git_output", lambda *_args: "unknown")
    monkeypatch.delenv("VIOLIN_SOURCE_COMMIT", raising=False)
    monkeypatch.setenv("VIOLIN_SOURCE_DIRTY", "false")
    manifest = _run_manifest(
        parse_args(["--target", "https://example.test"]),
        tmp_path / "run-1",
        public_key=b"public",
        started_at="2026-09-25T00:00:00+00:00",
    )
    assert manifest["source"]["git_commit"] == "unknown"
    assert manifest["source"]["git_dirty"] is False


def test_hermes_environment_forwards_only_selected_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "selected-key")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-leak")
    monkeypatch.setenv("NOUS_API_KEY", "other-provider-key")
    args = parse_args(
        [
            "--provider",
            "openrouter",
            "--api-base",
            "https://openrouter.ai/api/v1",
        ]
    )

    env = _hermes_environment(args, tmp_path, b"s" * 32)

    assert env["OPENROUTER_API_KEY"] == "selected-key"
    assert env["OPENAI_API_KEY"] == "selected-key"
    assert env["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"
    assert "NOUS_API_KEY" not in env
    assert "UNRELATED_SECRET" not in env


def test_agent_scope_rewrites_openapi_input_for_an_isolated_target() -> None:
    scope = _scope_for_target("http://localhost:8080")
    assert scope["benchmark"]["openapi_spec"] == "http://localhost:8080/openapi.json"
    brief = scope["engagement"]["brief"]
    assert "http://localhost:8080/openapi.json" in brief
    assert "https://duck-store.escape.tech" not in brief


def test_initialized_hypothesis_board_has_no_evaluator_fields(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    init_benchmark_engagement(engagement, "https://duck-store.escape.tech")
    board = (engagement / "hypotheses.md").read_text(encoding="utf-8").casefold()
    assert "challenge" not in board
    assert "golden" not in board
