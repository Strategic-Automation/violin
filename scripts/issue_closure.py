#!/usr/bin/env python3
"""Keep issue closure honest when pull requests do not target the default branch.

GitHub closes an issue from a closing keyword only when that keyword reaches the
repository's *default* branch. Violin merges feature work into ``dev`` and
releases ``dev`` into ``master``, so nothing closes an issue on its own. This
module supplies both halves of the fix:

``close-merged``
    Runs when a pull request merges into ``dev``. The issues that pull request
    claims are closed with a comment naming the merge, so the tracker reflects
    work that has landed.

``check-release``
    Guards the ``dev`` -> ``master`` release pull request, which is the one place
    GitHub's own closing keywords take effect. It must claim every issue the
    shipped pull requests claim, so the release closes anything the merge-time
    pass left behind.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# GitHub's closing keywords, as documented for "Linking a pull request to an issue".
CLOSING_KEYWORDS = frozenset(
    {"close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved"}
)
# Punctuation that may trail an issue reference without ending the reference list.
REFERENCE_PUNCTUATION = ".,;:"
# Words that join two references in the same list: "Closes #1, #2, and #3".
REFERENCE_CONJUNCTIONS = frozenset({"and", "&"})

SubjectReader = Callable[[str, str], list[str]]


def claimed_issues(body: str | None) -> set[int]:
    """Return the issue numbers a pull-request description claims to close.

    Only lines that open with a closing keyword are read, so a passing mention
    such as ``see #123`` never counts as a claim. Quoted templates and code
    samples are ignored, because the repository's own template shows the keyword
    without an issue number.
    """

    text = _without_fenced_blocks(_without_html_comments(body or ""))
    claimed: set[int] = set()
    for line in text.splitlines():
        remainder = _claim_remainder(line)
        if remainder is not None:
            claimed.update(_leading_issues(remainder))
    return claimed


def shipped_pull_requests(subjects: Iterable[str]) -> list[int]:
    """Return the pull-request numbers of squash-merged subjects, in order."""

    numbers: list[int] = []
    for subject in subjects:
        number = _squash_merge_number(subject.strip())
        if number is not None:
            numbers.append(number)
    return numbers


def _claim_remainder(line: str) -> str | None:
    """Return the text after a line-leading closing keyword, if there is one."""

    parts = line.strip().split(maxsplit=1)
    if not parts or parts[0].rstrip(":").lower() not in CLOSING_KEYWORDS:
        return None
    return parts[1] if len(parts) > 1 else ""


def _leading_issues(remainder: str) -> list[int]:
    """Return the issue numbers in the reference list that opens ``remainder``.

    The list ends at the first token that is neither a reference, a conjunction
    nor another closing keyword, so prose on the same line never joins it:
    ``Closes #138. Targets dev; nothing overlaps #145.`` claims #138 alone.

    A repeated keyword continues the list, because GitHub documents the full
    syntax for each issue: ``Closes #1, Closes #2`` claims both.
    """

    numbers: list[int] = []
    for token in remainder.split():
        word = token.strip(REFERENCE_PUNCTUATION)
        if not word:
            # A token of punctuation alone, as in "#1 , #2".
            continue
        if word.lower() in REFERENCE_CONJUNCTIONS or word.lower() in CLOSING_KEYWORDS:
            continue
        number = _issue_number(word)
        if number is None:
            break
        numbers.append(number)
    return numbers


def _issue_number(word: str) -> int | None:
    """Return the number of a ``#123`` reference, or ``None`` for any other word."""

    digits = word[1:] if word.startswith("#") else ""
    return int(digits) if digits.isdigit() else None


def _squash_merge_number(subject: str) -> int | None:
    """Return the pull-request number a squash-merge subject ends with."""

    if not subject.endswith(")"):
        return None
    start = subject.rfind("(#")
    if start < 0:
        return None
    digits = subject[start + 2 : -1]
    return int(digits) if digits.isdigit() else None


def _without_html_comments(body: str) -> str:
    """Drop ``<!-- ... -->`` spans, which quote the template without a reference."""

    text = body
    while True:
        start = text.find("<!--")
        if start < 0:
            return text
        end = text.find("-->", start + len("<!--"))
        if end < 0:
            return text[:start]
        text = text[:start] + text[end + len("-->") :]


def _without_fenced_blocks(body: str) -> str:
    """Drop fenced code blocks, which may quote a closing line as an example."""

    kept: list[str] = []
    in_fence = False
    for line in body.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            kept.append(line)
    return "\n".join(kept)


class GitHubClient:
    """Read and write one repository through the ``gh`` CLI."""

    def __init__(self, repository: str) -> None:
        self.repository = repository

    def get(self, path: str) -> Any:
        return self._call("GET", path)

    def post(self, path: str, payload: dict[str, object]) -> Any:
        return self._call("POST", path, payload)

    def patch(self, path: str, payload: dict[str, object]) -> Any:
        return self._call("PATCH", path, payload)

    def _call(self, method: str, path: str, payload: dict[str, object] | None = None) -> Any:
        command = ["gh", "api", "--method", method, f"repos/{self.repository}/{path}"]
        if payload is not None:
            command += ["--input", "-"]
        completed = subprocess.run(
            command,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(f"gh api {method} {path} failed: {detail}")
        return json.loads(completed.stdout or "null")


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


def _git(*arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments)} failed: {completed.stderr.strip()}")
    return completed.stdout


@dataclass(frozen=True)
class ReleaseGateReport:
    """The issues a release must claim, the ones it does claim, and the gap."""

    required: tuple[int, ...]
    provided: tuple[int, ...]
    missing: tuple[int, ...]

    @property
    def closing_line(self) -> str:
        """A ready-to-paste closing line for the missing issues.

        GitHub interprets a closing keyword only for the reference that follows
        it, so the keyword is repeated per issue (``Closes #1, Closes #2``)
        instead of listed once (``Closes #1, #2``), which would close only the
        first.
        """

        if not self.missing:
            return ""
        return ", ".join(f"Closes #{number}" for number in self.missing)


@dataclass(frozen=True)
class ClosureReport:
    """The issues a merged pull request closed, and the ones already closed."""

    pull_request: int
    closed: tuple[int, ...]
    already_closed: tuple[int, ...]
    dry_run: bool = False


def evaluate_release_issues(
    release_body: str | None,
    pull_requests: Iterable[int],
    api: GitHubClient,
    default_branch: str = "master",
) -> ReleaseGateReport:
    """Compare a release description against the claims of the shipped work.

    Release pull requests are skipped: they carry their own closing keywords and
    were already counted by the release that shipped them. Issues that are
    already closed are skipped too, so an issue closed by hand or by the
    merge-time pass never blocks a later release.
    """

    required: set[int] = set()
    for number in pull_requests:
        pull_request = api.get(f"pulls/{number}")
        if not isinstance(pull_request, dict):
            continue
        base = pull_request.get("base")
        if isinstance(base, dict) and base.get("ref") == default_branch:
            continue
        required |= claimed_issues(pull_request.get("body"))

    still_open = {number for number in required if _issue_state(api, number) == "open"}
    provided = claimed_issues(release_body)
    return ReleaseGateReport(
        required=tuple(sorted(still_open)),
        provided=tuple(sorted(provided)),
        missing=tuple(sorted(still_open - provided)),
    )


def close_merged_issues(
    pull_request_number: int,
    api: GitHubClient,
    *,
    dry_run: bool = False,
) -> ClosureReport:
    """Close the open issues a merged pull request claims, and say what changed."""

    pull_request = api.get(f"pulls/{pull_request_number}")
    if not isinstance(pull_request, dict):
        raise RuntimeError(f"pull request #{pull_request_number} could not be read")
    if not dry_run and not pull_request.get("merged_at"):
        raise RuntimeError(
            f"pull request #{pull_request_number} is not merged; refusing to close its issues"
        )

    closed: list[int] = []
    already_closed: list[int] = []
    for number in sorted(claimed_issues(pull_request.get("body"))):
        issue = api.get(f"issues/{number}")
        if not isinstance(issue, dict) or "pull_request" in issue:
            continue
        if issue.get("state") != "open":
            already_closed.append(number)
            continue
        if not dry_run:
            api.post(
                f"issues/{number}/comments",
                {"body": _closure_comment(pull_request_number, pull_request)},
            )
            api.patch(f"issues/{number}", {"state": "closed", "state_reason": "completed"})
        closed.append(number)

    return ClosureReport(
        pull_request=pull_request_number,
        closed=tuple(closed),
        already_closed=tuple(already_closed),
        dry_run=dry_run,
    )


def _closure_comment(pull_request_number: int, pull_request: dict[str, Any]) -> str:
    """Return the comment that records why an issue was closed."""

    title = pull_request.get("title") or ""
    commit = pull_request.get("merge_commit_sha") or ""
    lines = [
        f"Closed as completed by #{pull_request_number}: {title}",
        "",
        "The fix merged into `dev`, which is not this repository's default branch, "
        "so GitHub's own closing keywords do not apply to it. The merge-time "
        "workflow in `.github/workflows/close-merged-issues.yml` applied the close.",
    ]
    if commit:
        lines += ["", f"Merge commit: `{commit}`"]
    return "\n".join(lines)


def _issue_state(api: GitHubClient, number: int) -> str:
    issue = api.get(f"issues/{number}")
    return issue.get("state", "") if isinstance(issue, dict) else ""


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Close issues across the dev/release flow.")
    commands = parser.add_subparsers(dest="command", required=True)

    merged = commands.add_parser(
        "close-merged", help="close the open issues a merged pull request claims"
    )
    merged.add_argument("--pr", type=int, required=True, help="the merged pull request number")
    merged.add_argument("--dry-run", action="store_true", help="report without closing anything")

    release = commands.add_parser(
        "check-release", help="fail when a release description omits a shipped issue"
    )
    release.add_argument("--body-file", required=True, help="the release pull-request description")
    release.add_argument(
        "--base", help="range start; defaults to the latest release tag reachable from --head"
    )
    release.add_argument("--head", default="origin/dev", help="range end (default: origin/dev)")
    release.add_argument(
        "--default-branch", default="master", help="default branch (default: master)"
    )

    for command in (merged, release):
        command.add_argument("--repo", help="owner/name; defaults to the repository gh resolves")
    return parser


def _run_close_merged(arguments: argparse.Namespace, api: GitHubClient) -> int:
    report = close_merged_issues(arguments.pr, api, dry_run=arguments.dry_run)
    verb = "would close" if report.dry_run else "closed"
    if report.closed:
        print(f"{verb.capitalize()} {', '.join(f'#{number}' for number in report.closed)}.")
    else:
        print(f"#{report.pull_request} claims no open issue; nothing to close.")
    if report.already_closed:
        already = ", ".join(f"#{number}" for number in report.already_closed)
        print(f"Already closed: {already}.")
    return 0


def _run_check_release(
    arguments: argparse.Namespace, api: GitHubClient, subjects: SubjectReader
) -> int:
    body = Path(arguments.body_file).read_text(encoding="utf-8")
    base = arguments.base or default_release_base(arguments.head)
    pull_requests = shipped_pull_requests(subjects(base, arguments.head))
    report = evaluate_release_issues(body, pull_requests, api, arguments.default_branch)

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


def main(
    argv: Sequence[str] | None = None,
    *,
    api: GitHubClient | None = None,
    subjects: SubjectReader = commit_subjects,
) -> int:
    """Run the requested command and return its exit code."""

    arguments = _build_parser().parse_args(argv)
    client = api or GitHubClient(arguments.repo or _resolve_repository())
    try:
        if arguments.command == "close-merged":
            return _run_close_merged(arguments, client)
        return _run_check_release(arguments, client, subjects)
    except RuntimeError as error:
        print(f"::error::{error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
