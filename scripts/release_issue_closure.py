#!/usr/bin/env python3
"""Fail a release pull request that omits the issues its shipped work claims.

GitHub closes an issue from a closing keyword only when that keyword reaches the
repository's *default* branch. Feature pull requests target ``dev``, so ``Fixes
#123`` on a topic branch records an intent and closes nothing: the release pull
request (``dev`` -> ``master``) is the only place where the keywords take effect.
This script collects the issues claimed by the pull requests shipped since the
last release tag and reports the ones the release description does not claim, so
that merging the release closes them automatically.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

# GitHub's closing keywords, as documented for "Linking a pull request to an issue".
CLOSING_KEYWORD_PATTERN = r"close[sd]?|fix(?:e[sd])?|resolve[sd]?"

_CLAIM_START = re.compile(rf"(?im)^[^\S\n]*(?:{CLOSING_KEYWORD_PATTERN})\b[ \t]*:?[ \t]*")
_ISSUE_REFERENCE = re.compile(r"#(\d+)")
# The reference list that follows a keyword: issue numbers joined by commas or
# "and", which is as far as GitHub reads. It ends at the first other token, so
# "Closes #138. Nothing overlaps #145." claims #138 alone.
_REFERENCE_RUN = re.compile(r"^(?:(?:[ \t]*(?:,|and|&))*[ \t]*#\d+)+")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_CODE_FENCE = re.compile(r"^[ \t]*```.*?^[ \t]*```", re.DOTALL | re.MULTILINE)
_SQUASH_MERGE_SUFFIX = re.compile(r"\(#(\d+)\)\s*$")

ApiCall = Callable[[str], object]
SubjectReader = Callable[[str, str], list[str]]


def _leading_references(remainder: str) -> list[int]:
    """Return the issue numbers in the reference list that opens ``remainder``."""

    run = _REFERENCE_RUN.match(remainder)
    return [int(number) for number in _ISSUE_REFERENCE.findall(run.group())] if run else []


def claimed_issues(body: str | None) -> set[int]:
    """Return the issue numbers a pull-request description claims to close.

    Only lines that open with a closing keyword are read, so a passing mention
    such as ``see #123`` never counts as a claim. Quoted templates and code
    samples are ignored, because the repository's own template shows the keyword
    without an issue number.
    """

    text = _CODE_FENCE.sub("", _HTML_COMMENT.sub("", body or ""))
    claimed: set[int] = set()
    for line in text.splitlines():
        head = _CLAIM_START.match(line)
        if head:
            claimed.update(_leading_references(line[head.end() :]))
    return claimed


def shipped_pull_requests(subjects: Iterable[str]) -> list[int]:
    """Return the pull-request numbers of squash-merged subjects, in order."""

    numbers: list[int] = []
    for subject in subjects:
        match = _SQUASH_MERGE_SUFFIX.search(subject.strip())
        if match:
            numbers.append(int(match.group(1)))
    return numbers


@dataclass(frozen=True)
class ReleaseIssueReport:
    """The issues a release must claim, the ones it does claim, and the gap."""

    required: tuple[int, ...]
    provided: tuple[int, ...]
    missing: tuple[int, ...]

    @property
    def closing_line(self) -> str:
        """A ready-to-paste closing line for the missing issues."""

        return "Closes " + ", ".join(f"#{number}" for number in self.missing)


def evaluate_release_issues(
    release_body: str | None,
    pull_requests: Iterable[int],
    api: ApiCall,
    default_branch: str = "master",
) -> ReleaseIssueReport:
    """Compare a release description against the claims of the shipped work.

    Release pull requests are skipped: they carry their own closing keywords and
    were already counted by the release that shipped them. Issues that are
    already closed are skipped too, so an issue closed by hand never blocks a
    later release.
    """

    required: set[int] = set()
    for number in pull_requests:
        pull_request = api(f"pulls/{number}")
        if not isinstance(pull_request, dict):
            continue
        base = pull_request.get("base")
        if isinstance(base, dict) and base.get("ref") == default_branch:
            continue
        required |= claimed_issues(pull_request.get("body"))

    still_open = {number for number in required if _issue_is_open(api, number)}
    provided = claimed_issues(release_body)
    return ReleaseIssueReport(
        required=tuple(sorted(still_open)),
        provided=tuple(sorted(provided)),
        missing=tuple(sorted(still_open - provided)),
    )


def _issue_is_open(api: ApiCall, number: int) -> bool:
    issue = api(f"issues/{number}")
    return isinstance(issue, dict) and issue.get("state") == "open"


def github_api(repository: str) -> ApiCall:
    """Return an ``api`` callable that reads one repository through ``gh``."""

    def call(path: str) -> object:
        completed = subprocess.run(
            ["gh", "api", f"repos/{repository}/{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(f"gh api {path} failed: {detail}")
        return json.loads(completed.stdout or "null")

    return call


def _git(*arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments)} failed: {completed.stderr.strip()}")
    return completed.stdout


def commit_subjects(base: str, head: str) -> list[str]:
    """Return the commit subjects in ``base..head``."""

    return [line for line in _git("log", "--format=%s", f"{base}..{head}").splitlines() if line]


def latest_release_tag(head: str) -> str | None:
    """Return the most recent tag reachable from ``head``, if any."""

    completed = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0", head],
        capture_output=True,
        text=True,
        check=False,
    )
    tag = completed.stdout.strip()
    return tag if completed.returncode == 0 and tag else None


def default_release_base(head: str) -> str:
    """Return the start of the range that a release ships.

    The last release tag is exact once the repository has released at least once;
    before that, the point where ``dev`` last agreed with ``master`` is the best
    available boundary.
    """

    tag = latest_release_tag(head)
    if tag:
        return tag
    return _git("merge-base", "origin/master", head).strip()


def _resolve_repository() -> str:
    completed = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        capture_output=True,
        text=True,
        check=False,
    )
    repository = completed.stdout.strip()
    if completed.returncode != 0 or not repository:
        raise RuntimeError("could not resolve the repository; pass --repo owner/name")
    return repository


def main(
    argv: Sequence[str] | None = None,
    *,
    api: ApiCall | None = None,
    subjects: SubjectReader = commit_subjects,
) -> int:
    """Report the shipped issues the release description does not claim."""

    parser = argparse.ArgumentParser(description="Check release pull-request issue claims.")
    parser.add_argument(
        "--body-file", required=True, help="File holding the release pull-request description."
    )
    parser.add_argument("--repo", help="owner/name; defaults to the repository gh resolves.")
    parser.add_argument(
        "--base", help="Range start; defaults to the latest release tag reachable from --head."
    )
    parser.add_argument("--head", default="origin/dev", help="Range end (default: origin/dev).")
    parser.add_argument(
        "--default-branch", default="master", help="Default branch (default: master)."
    )
    arguments = parser.parse_args(argv)

    repository = arguments.repo or _resolve_repository()
    body = Path(arguments.body_file).read_text(encoding="utf-8")
    base = arguments.base or default_release_base(arguments.head)
    pull_requests = shipped_pull_requests(subjects(base, arguments.head))
    report = evaluate_release_issues(
        body, pull_requests, api or github_api(repository), arguments.default_branch
    )

    print(
        f"Release range {base}..{arguments.head}: {len(pull_requests)} pull request(s), "
        f"{len(report.required)} issue(s) to close."
    )
    if not report.required:
        print("OK: no shipped pull request claims an open issue.")
        return 0
    if report.missing:
        print("::error::The release description does not claim every shipped issue.")
        for number in report.missing:
            print(
                f"::error::Issue #{number} is claimed by a shipped pull request "
                "but not by this release description."
            )
        print(f"Add this line to the release description: {report.closing_line}")
        return 1

    print(
        "OK: the release description claims "
        + ", ".join(f"#{number}" for number in report.required)
        + "; merging into the default branch closes them."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
