"""The live GitHub benchmark must execute and gate the pinned Docker runtime."""

from pathlib import Path

import yaml


def test_live_benchmark_runs_in_docker_and_requires_host_evaluation() -> None:
    workflow_path = Path(__file__).parents[2] / ".github" / "workflows" / "benchmark.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["benchmark"]["steps"]
    run_steps = {step["name"]: step.get("run", "") for step in steps}

    live_run = run_steps["Run Live Benchmark in Docker"]
    assert "docker run" in live_run
    assert "uv run --no-dev python -m benchmark.run" in live_run
    assert "--env OPENROUTER_API_KEY" in live_run
    assert "--target-isolation-id" in live_run
    assert 'jq -e ".benchmark_pass == true"' in live_run
    assert not any(
        "uv run python benchmark/run.py" in script or "uv run python -m benchmark.run" in script
        for name, script in run_steps.items()
        if name != "Run Live Benchmark in Docker"
    )
    assert "Check Hermes Availability" not in run_steps
    assert "Score-Only Fallback (No Hermes)" not in run_steps
