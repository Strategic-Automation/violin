"""Release pull requests must claim every issue their shipped work closes."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.release_issue_closure import (
    ReleaseIssueReport,
    claimed_issues,
    evaluate_release_issues,
    main,
    shipped_pull_requests,
)

ROOT = Path(__file__).resolve().parents[1]
OPEN = {"state": "open"}
CLOSED = {"state": "closed"}


def _api(routes: dict[str, object]) -> object:
    def call(path: str) -> object:
        return routes[path]

    return call


def test_claimed_issues_reads_every_closing_keyword() -> None:
    body = "\n".join(
        [
            "Fixes #83",
            "Closes #1, #2",
            "resolved: #9",
            "Fixed #7 and #8",
            "closed #10",
            "Resolves #11",
        ]
    )

    assert claimed_issues(body) == {1, 2, 7, 8, 9, 10, 11, 83}


def test_claimed_issues_ignores_mentions_quotes_and_placeholders() -> None:
    body = "\n".join(
        [
            "Related to #5",
            "see #123",
            "<!-- Closes #6 -->",
            "```",
            "Closes #4",
            "```",
            "Fixes #",
            "This change does not close #12 yet.",
        ]
    )

    assert claimed_issues(body) == set()


def test_prose_on_the_claim_line_does_not_join_the_reference_list() -> None:
    body = (
        "Closes #138. Targets `dev` from `codex/review-benchmark-ast`; "
        "none of the four changed files overlaps #145."
    )

    assert claimed_issues(body) == {138}


def test_words_after_the_reference_list_do_not_join_it() -> None:
    assert claimed_issues("Fixes #83 and see #84 for context") == {83}
    assert claimed_issues("Closes #1, #2, and #3 plus #4") == {1, 2, 3}


def test_shipped_pull_requests_reads_squash_merge_subjects() -> None:
    subjects = [
        "fix: correlate finding evidence (#160)",
        "docs: improve Violin discovery and conversion",
        "chore(deps): bump filelock in the python-dependencies group (#157)",
        "Merge pull request #161 from Strategic-Automation/dev",
    ]

    assert shipped_pull_requests(subjects) == [160, 157]


def test_release_pull_requests_do_not_require_their_own_issues() -> None:
    routes = {
        "pulls/161": {"base": {"ref": "master"}, "body": "Closes #40"},
    }

    report = evaluate_release_issues("", [161], _api(routes))

    assert report.required == ()
    assert report.missing == ()


def test_missing_issue_is_reported_with_a_paste_ready_line() -> None:
    routes = {
        "pulls/160": {"base": {"ref": "dev"}, "body": "Fixes #83\nFixes #84"},
        "pulls/146": {"base": {"ref": "dev"}, "body": "Closes #138"},
        "issues/83": OPEN,
        "issues/84": OPEN,
        "issues/138": OPEN,
    }

    report = evaluate_release_issues("Closes #83", [160, 146], _api(routes))

    assert report.required == (83, 84, 138)
    assert report.provided == (83,)
    assert report.missing == (84, 138)
    assert report.closing_line == "Closes #84, #138"


def test_closed_issue_is_not_required() -> None:
    routes = {
        "pulls/146": {"base": {"ref": "dev"}, "body": "Closes #138"},
        "issues/138": CLOSED,
    }

    report = evaluate_release_issues("", [146], _api(routes))

    assert report.required == ()
    assert report.missing == ()


def test_claim_without_an_open_issue_is_not_required() -> None:
    routes = {
        "pulls/129": {"base": {"ref": "dev"}, "body": "References #127"},
        "issues/127": OPEN,
    }

    report = evaluate_release_issues("", [129], _api(routes))

    assert report.required == ()
    assert report.missing == ()


def test_main_fails_and_prints_the_line_to_add(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    body_file = tmp_path / "release-body.md"
    body_file.write_text("## Summary\n\nRelease the guard fixes.\n", encoding="utf-8")
    routes = {
        "pulls/160": {"base": {"ref": "dev"}, "body": "Fixes #83"},
        "issues/83": OPEN,
    }

    exit_code = main(
        [
            "--body-file",
            str(body_file),
            "--repo",
            "Strategic-Automation/violin",
            "--base",
            "v3.3.2",
        ],
        api=_api(routes),
        subjects=lambda base, head: ["fix: correlate finding evidence (#160)"],
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "::error::Issue #83 is claimed by a shipped pull request" in output
    assert "Add this line to the release description: Closes #83" in output


def test_main_passes_when_every_shipped_issue_is_claimed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    body_file = tmp_path / "release-body.md"
    body_file.write_text("Closes #83, #84\n", encoding="utf-8")
    routes = {
        "pulls/160": {"base": {"ref": "dev"}, "body": "Fixes #83\nFixes #84"},
        "issues/83": OPEN,
        "issues/84": OPEN,
    }

    exit_code = main(
        [
            "--body-file",
            str(body_file),
            "--repo",
            "Strategic-Automation/violin",
            "--base",
            "v3.3.2",
        ],
        api=_api(routes),
        subjects=lambda base, head: ["fix: correlate finding evidence (#160)"],
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "OK: the release description claims #83, #84" in output


def test_main_accepts_a_release_with_nothing_to_close(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    body_file = tmp_path / "release-body.md"
    body_file.write_text("## Summary\n\nRelease documentation only.\n", encoding="utf-8")

    exit_code = main(
        [
            "--body-file",
            str(body_file),
            "--repo",
            "Strategic-Automation/violin",
            "--base",
            "v3.3.2",
        ],
        api=_api({}),
        subjects=lambda base, head: ["docs: improve discovery"],
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "OK: no shipped pull request claims an open issue." in output


def test_report_closing_line_is_empty_without_a_gap() -> None:
    report = ReleaseIssueReport(required=(83,), provided=(83,), missing=())

    assert report.closing_line == "Closes "


def test_release_issues_job_wires_the_check_to_release_pull_requests() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "pr-verify.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["release-issues"]

    assert job["if"] == "github.event.pull_request.base.ref == 'master'"
    assert any("release_issue_closure.py" in step.get("run", "") for step in job["steps"]), (
        "the release-issues job must run scripts/release_issue_closure.py"
    )
