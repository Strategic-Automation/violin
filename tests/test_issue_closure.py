"""Issues close when the work merges into dev, and the release claims any leftovers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.issue_closure import (
    ClosureReport,
    GitHubClient,
    ReleaseGateReport,
    claimed_issues,
    close_merged_issues,
    evaluate_release_issues,
    main,
    shipped_pull_requests,
)

ROOT = Path(__file__).resolve().parents[1]
OPEN = {"state": "open"}
CLOSED = {"state": "closed"}


class StubClient:
    """A ``GitHubClient`` stand-in that answers from a route map and records writes."""

    def __init__(self, routes: dict[str, Any] | None = None) -> None:
        self.routes = routes or {}
        self.writes: list[tuple[str, str, dict[str, object]]] = []

    def get(self, path: str) -> Any:
        return self.routes[path]

    def post(self, path: str, payload: dict[str, object]) -> Any:
        self.writes.append(("POST", path, payload))
        return {}

    def patch(self, path: str, payload: dict[str, object]) -> Any:
        self.writes.append(("PATCH", path, payload))
        return {}


# --- reading closing keywords -------------------------------------------------


def test_claimed_issues_reads_every_closing_keyword() -> None:
    body = "\n".join(
        [
            "Fixes #83",
            "Closes #1, #2",
            "resolved: #9",
            "Fixed #7 and #8",
            "closed #10",
            "Resolves #11",
            "CLOSES: #12",
        ]
    )

    assert claimed_issues(body) == {1, 2, 7, 8, 9, 10, 11, 12, 83}


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
            "Closes the gap in #13.",
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


def test_the_full_syntax_for_each_issue_is_read() -> None:
    # GitHub closes only the reference that follows a keyword, so a release
    # description repeats the keyword per issue.
    assert claimed_issues("Closes #1, Closes #2, Closes #3") == {1, 2, 3}
    assert claimed_issues("Closes #1 , closes #2") == {1, 2}
    # A reference in another repository is outside this gate's scope.
    assert claimed_issues("Fixes #83, fixes octo-org/other#84") == {83}


def test_shipped_pull_requests_reads_squash_merge_subjects() -> None:
    subjects = [
        "fix: correlate finding evidence (#160)",
        "docs: improve Violin discovery and conversion",
        "chore(deps): bump filelock in the python-dependencies group (#157)",
        "Merge pull request #161 from Strategic-Automation/dev",
    ]

    assert shipped_pull_requests(subjects) == [160, 157]


# --- closing on merge into dev ------------------------------------------------


def _merged_pull_request(body: str) -> dict[str, Any]:
    return {
        "number": 160,
        "title": "fix: correlate finding evidence",
        "body": body,
        "merged_at": "2026-09-22T09:00:00Z",
        "merge_commit_sha": "a" * 40,
        "base": {"ref": "dev"},
    }


def test_closing_a_merged_pull_request_comments_and_completes_the_issue() -> None:
    api = StubClient(
        {
            "pulls/160": _merged_pull_request("Fixes #83\nFixes #84"),
            "issues/83": OPEN,
            "issues/84": {"state": "closed"},
        }
    )

    report = close_merged_issues(160, api)  # type: ignore[arg-type]

    assert report == ClosureReport(pull_request=160, closed=(83,), already_closed=(84,))
    assert [write[0] for write in api.writes] == ["POST", "PATCH"]
    assert api.writes[0][1] == "issues/83/comments"
    assert "Closed as completed by #160" in api.writes[0][2]["body"]
    assert api.writes[1] == ("PATCH", "issues/83", {"state": "closed", "state_reason": "completed"})


def test_a_dry_run_reports_the_issues_without_writing() -> None:
    api = StubClient({"pulls/160": _merged_pull_request("Fixes #83"), "issues/83": OPEN})

    report = close_merged_issues(160, api, dry_run=True)  # type: ignore[arg-type]

    assert report.closed == (83,)
    assert report.dry_run is True
    assert api.writes == []


def test_references_to_pull_requests_are_never_closed() -> None:
    api = StubClient(
        {
            "pulls/160": _merged_pull_request("Fixes #160"),
            "issues/160": {"state": "open", "pull_request": {"url": "..."}},
        }
    )

    report = close_merged_issues(160, api)  # type: ignore[arg-type]

    assert report.closed == ()
    assert api.writes == []


def test_an_unmerged_pull_request_cannot_close_anything() -> None:
    unmerged = _merged_pull_request("Fixes #83")
    unmerged["merged_at"] = None
    api = StubClient({"pulls/160": unmerged, "issues/83": OPEN})

    with pytest.raises(RuntimeError, match="is not merged"):
        close_merged_issues(160, api)  # type: ignore[arg-type]

    assert api.writes == []


def test_a_dry_run_may_read_an_unmerged_pull_request() -> None:
    unmerged = _merged_pull_request("Fixes #83")
    unmerged["merged_at"] = None
    api = StubClient({"pulls/160": unmerged, "issues/83": OPEN})

    report = close_merged_issues(160, api, dry_run=True)  # type: ignore[arg-type]

    assert report.closed == (83,)
    assert api.writes == []


def test_a_pull_request_that_claims_nothing_closes_nothing() -> None:
    api = StubClient({"pulls/156": _merged_pull_request("## Summary\n\nNo issue.")})

    report = close_merged_issues(156, api)  # type: ignore[arg-type]

    assert report.closed == ()
    assert report.already_closed == ()
    assert api.writes == []


# --- the release gate ---------------------------------------------------------


def test_release_pull_requests_do_not_require_their_own_issues() -> None:
    api = StubClient({"pulls/161": {"base": {"ref": "master"}, "body": "Closes #40"}})

    report = evaluate_release_issues("", [161], api)  # type: ignore[arg-type]

    assert report.required == ()
    assert report.missing == ()


def test_missing_issue_is_reported_with_a_paste_ready_line() -> None:
    api = StubClient(
        {
            "pulls/160": {"base": {"ref": "dev"}, "body": "Fixes #83\nFixes #84"},
            "pulls/146": {"base": {"ref": "dev"}, "body": "Closes #138"},
            "issues/83": OPEN,
            "issues/84": OPEN,
            "issues/138": OPEN,
        }
    )

    report = evaluate_release_issues("Closes #83", [160, 146], api)  # type: ignore[arg-type]

    assert report.required == (83, 84, 138)
    assert report.provided == (83,)
    assert report.missing == (84, 138)
    assert report.closing_line == "Closes #84, Closes #138"


def test_an_issue_closed_by_the_merge_time_pass_is_not_required_again() -> None:
    api = StubClient(
        {"pulls/146": {"base": {"ref": "dev"}, "body": "Closes #138"}, "issues/138": CLOSED}
    )

    report = evaluate_release_issues("", [146], api)  # type: ignore[arg-type]

    assert report.required == ()
    assert report.missing == ()


def test_a_claim_without_an_open_issue_is_not_required() -> None:
    api = StubClient(
        {"pulls/129": {"base": {"ref": "dev"}, "body": "References #127"}, "issues/127": OPEN}
    )

    report = evaluate_release_issues("", [129], api)  # type: ignore[arg-type]

    assert report.required == ()
    assert report.missing == ()


# --- command line -------------------------------------------------------------


def test_close_merged_prints_the_issues_it_closed(capsys: pytest.CaptureFixture) -> None:
    api = StubClient({"pulls/160": _merged_pull_request("Fixes #83"), "issues/83": OPEN})

    exit_code = main(["close-merged", "--pr", "160"], api=api)  # type: ignore[arg-type]

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Closed #83." in output
    assert api.writes[1][2]["state_reason"] == "completed"


def test_close_merged_dry_run_says_what_it_would_close(capsys: pytest.CaptureFixture) -> None:
    api = StubClient({"pulls/160": _merged_pull_request("Fixes #83"), "issues/83": OPEN})

    exit_code = main(["close-merged", "--pr", "160", "--dry-run"], api=api)  # type: ignore[arg-type]

    assert exit_code == 0
    assert "Would close #83." in capsys.readouterr().out
    assert api.writes == []


def test_close_merged_reports_an_unmerged_pull_request_cleanly(
    capsys: pytest.CaptureFixture,
) -> None:
    unmerged = _merged_pull_request("Fixes #83")
    unmerged["merged_at"] = None
    api = StubClient({"pulls/160": unmerged, "issues/83": OPEN})

    exit_code = main(["close-merged", "--pr", "160"], api=api)  # type: ignore[arg-type]

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "::error::pull request #160 is not merged; refusing to close its issues" in output
    assert api.writes == []


def test_check_release_fails_and_prints_the_line_to_add(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    body_file = tmp_path / "release-body.md"
    body_file.write_text("## Summary\n\nRelease the guard fixes.\n", encoding="utf-8")
    api = StubClient(
        {"pulls/160": {"base": {"ref": "dev"}, "body": "Fixes #83"}, "issues/83": OPEN}
    )

    exit_code = main(
        ["check-release", "--body-file", str(body_file), "--base", "v3.3.2"],
        api=api,  # type: ignore[arg-type]
        subjects=lambda base, head: ["fix: correlate finding evidence (#160)"],
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "::error::Issue #83 is claimed by a shipped pull request" in output
    assert "Add this line to the release description: Closes #83" in output


def test_check_release_passes_when_every_shipped_issue_is_claimed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    body_file = tmp_path / "release-body.md"
    body_file.write_text("Closes #83, #84\n", encoding="utf-8")
    api = StubClient(
        {
            "pulls/160": {"base": {"ref": "dev"}, "body": "Fixes #83\nFixes #84"},
            "issues/83": OPEN,
            "issues/84": OPEN,
        }
    )

    exit_code = main(
        ["check-release", "--body-file", str(body_file), "--base", "v3.3.2"],
        api=api,  # type: ignore[arg-type]
        subjects=lambda base, head: ["fix: correlate finding evidence (#160)"],
    )

    assert exit_code == 0
    assert "OK: the release description claims #83, #84" in capsys.readouterr().out


def test_check_release_accepts_a_release_with_nothing_to_close(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    body_file = tmp_path / "release-body.md"
    body_file.write_text("## Summary\n\nRelease documentation only.\n", encoding="utf-8")

    exit_code = main(
        ["check-release", "--body-file", str(body_file), "--base", "v3.3.2"],
        api=StubClient(),  # type: ignore[arg-type]
        subjects=lambda base, head: ["docs: improve discovery"],
    )

    assert exit_code == 0
    assert "OK: no shipped pull request claims an open issue." in capsys.readouterr().out


def test_release_gate_report_has_no_closing_line_without_a_gap() -> None:
    report = ReleaseGateReport(required=(83,), provided=(83,), missing=())

    assert report.closing_line == ""


def test_the_closing_line_is_accepted_by_this_gate_and_by_github() -> None:
    report = ReleaseGateReport(required=(1, 2, 3), provided=(), missing=(1, 2, 3))

    line = report.closing_line

    # GitHub closes an issue only for the reference that follows a keyword, so
    # the keyword is repeated rather than the issues listed once.
    assert line == "Closes #1, Closes #2, Closes #3"
    assert claimed_issues(line) == {1, 2, 3}


# --- the workflows that call this -------------------------------------------------


def _workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def test_merged_pull_requests_close_their_issues_on_dev() -> None:
    document = _workflow("close-merged-issues.yml")
    trigger = document.get("on") or document.get(True)
    job = document["jobs"]["close"]

    assert trigger["pull_request_target"]["types"] == ["closed"]
    assert trigger["pull_request_target"]["branches"] == ["dev"]
    assert job["if"] == "github.event.pull_request.merged == true"
    assert job["permissions"]["issues"] == "write"
    assert job["permissions"]["contents"] == "read"
    assert any("issue_closure.py close-merged" in step.get("run", "") for step in job["steps"]), (
        "the close job must run scripts/issue_closure.py close-merged"
    )


def test_the_release_gate_still_runs_the_check_on_release_pull_requests() -> None:
    job = _workflow("pr-verify.yml")["jobs"]["release-issues"]

    assert job["if"] == "github.event.pull_request.base.ref == 'master'"
    assert any("issue_closure.py check-release" in step.get("run", "") for step in job["steps"]), (
        "the release-issues job must run scripts/issue_closure.py check-release"
    )


def test_the_client_is_the_shared_gh_backed_implementation() -> None:
    assert isinstance(GitHubClient("Strategic-Automation/violin"), GitHubClient)
