"""test_engagement_isolation.py — Unit tests for engagement path isolation and env resolution."""

from pathlib import Path

from plugins.violin_guard.core.state import resolve_eng_dir
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
