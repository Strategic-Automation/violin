"""The live GitHub benchmark must execute and gate the pinned Docker runtime."""

from pathlib import Path

import yaml


def test_live_benchmark_scores_runtime_output_in_separate_docker_image() -> None:
    workflow_path = Path(__file__).parents[2] / ".github" / "workflows" / "benchmark.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["benchmark"]["steps"]
    run_steps = {step["name"]: step.get("run", "") for step in steps}

    calibration = run_steps["Scorer Calibration Gate"]
    assert "docker run --rm --network none" in calibration
    assert "uv run pytest" not in calibration
    test_image = (workflow_path.parents[2] / "Dockerfile.test").read_text(encoding="utf-8")
    assert "uv run pytest tests/benchmark -q" in test_image
    assert "--calibrate known-good" in test_image
    assert "--calibrate known-bad" in test_image
    assert "git jq" in test_image
    dockerignore = (workflow_path.parents[2] / ".dockerignore").read_text(encoding="utf-8")
    assert ".pytest-*" in dockerignore
    assert ".benchmark-live" in dockerignore

    live_run = run_steps["Run Live Benchmark in Docker"]
    assert "docker run" in live_run
    assert "uv run --no-dev python -m benchmark.run" in live_run
    assert "--env OPENROUTER_API_KEY" in live_run
    assert "--target-isolation-id" in live_run
    assert "benchmark.score" not in live_run
    assert 'test -z "$(git status --porcelain)"' in run_steps["Build Violin Runtime Image"]
    assert '"VIOLIN_SOURCE_COMMIT=${GITHUB_SHA}"' in live_run
    assert "VIOLIN_SOURCE_DIRTY=false" in live_run
    assert '"VIOLIN_BENCHMARK_IMAGE_DIGEST=${RUNTIME_IMAGE_ID}"' in live_run
    assert '"$RUNTIME_IMAGE_ID"' in live_run

    evaluator = run_steps["Evaluate and Gate Live Benchmark in Docker"]
    assert "docker run --rm --network none" in evaluator
    assert "--env GITHUB_RUN_ID" in evaluator
    assert '"violin-tests:${GITHUB_SHA}"' in evaluator
    assert 'jq -e ".runner.valid == true"' in evaluator
    assert "uv run python -m benchmark.score" in evaluator
    assert 'jq -e ".benchmark_pass == true"' in evaluator

    runtime_dockerfile = (workflow_path.parents[2] / "Dockerfile").read_text(encoding="utf-8")
    assert "benchmark/private" not in runtime_dockerfile
    assert not any(
        "uv run python benchmark/run.py" in script or "uv run python -m benchmark.run" in script
        for name, script in run_steps.items()
        if name != "Run Live Benchmark in Docker"
    )
    assert "Check Hermes Availability" not in run_steps
    assert "Score-Only Fallback (No Hermes)" not in run_steps

    artifact = next(step for step in steps if step["name"] == "Upload Benchmark Artifacts")
    assert artifact["with"]["path"] == "engagements/benchmark_summary.md"
