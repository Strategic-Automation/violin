"""test_engagement_isolation.py — Unit tests for engagement path isolation and env resolution."""

from pathlib import Path

from plugins.violin_guard.core.engagement.state import resolve_eng_dir
from plugins.violin_guard.gates.command import check_cross_engagement_paths


def test_resolve_eng_dir_prioritizes_env(monkeypatch, tmp_path: Path) -> None:
    target_eng = tmp_path / "engagements" / "benchmark-run-testenv"
    target_eng.mkdir(parents=True, exist_ok=True)
    (target_eng / "scope").mkdir(parents=True, exist_ok=True)
    (target_eng / "scope" / "scope.yaml").write_text("dummy: true\n", encoding="utf-8")

    monkeypatch.setenv("ENG_DIR", str(target_eng))

    resolved = resolve_eng_dir("")
    assert resolved == target_eng.resolve()

    resolved_dot = resolve_eng_dir(".")
    assert resolved_dot == target_eng.resolve()


def test_relative_engagement_path_uses_profile_root_not_cwd(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "engagements").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIOLIN_ENG_ROOT", raising=False)

    assert (
        resolve_eng_dir("engagements/new")
        == (Path(__file__).resolve().parents[3] / "engagements" / "new").resolve()
    )


def test_resolve_eng_dir_honours_violin_eng_root(monkeypatch, tmp_path: Path) -> None:
    custom_root = tmp_path / "custom-violin-root"
    custom_eng = custom_root / "engagements" / "target-1"
    custom_eng.mkdir(parents=True, exist_ok=True)

    monkeypatch.delenv("ENG_DIR", raising=False)
    monkeypatch.setenv("VIOLIN_ENG_ROOT", str(custom_root))
    monkeypatch.chdir(tmp_path)

    # Relative path resolves against VIOLIN_ENG_ROOT
    assert resolve_eng_dir("engagements/target-1") == custom_eng.resolve()

    # Empty string and dot resolve to VIOLIN_ENG_ROOT when ENG_DIR is unset and cwd has no scope/hypotheses
    assert resolve_eng_dir("") == custom_root.resolve()
    assert resolve_eng_dir(".") == custom_root.resolve()


def test_resolve_eng_dir_does_not_redirect_explicit_path_to_environment(
    monkeypatch, tmp_path: Path
) -> None:
    target_eng = tmp_path / "engagements" / "benchmark-run-20260823_204011"
    (target_eng / "scope").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ENG_DIR", str(target_eng))

    mistyped = tmp_path / "engagements" / "benchmark-run-20260123_204011"  # does not exist
    assert resolve_eng_dir(str(mistyped)) == mistyped.resolve()


def test_check_cross_engagement_paths_blocks_foreign_dir(tmp_path: Path) -> None:
    active_dir = tmp_path / "engagements" / "benchmark-run-20260806_211041"
    active_dir.mkdir(parents=True, exist_ok=True)

    foreign_cmd = (
        "curl -sS https://duck-store.escape.tech/ -o "
        "/violin/engagements/benchmark-run-20260806_204547/evidence/recon/homepage.html"
    )

    result = check_cross_engagement_paths(foreign_cmd, active_dir)
    assert len(result.errors) == 1
    assert "cross-engagement path access blocked" in result.errors[0]
    assert "benchmark-run-20260806_204547" in result.errors[0]


def test_check_cross_engagement_paths_allows_matching_dir(tmp_path: Path) -> None:
    active_dir = tmp_path / "engagements" / "benchmark-run-20260806_211041"
    active_dir.mkdir(parents=True, exist_ok=True)

    valid_cmd = (
        "curl -sS https://duck-store.escape.tech/ -o "
        "/violin/engagements/benchmark-run-20260806_211041/evidence/recon/homepage.html"
    )

    result = check_cross_engagement_paths(valid_cmd, active_dir)
    assert len(result.errors) == 0
