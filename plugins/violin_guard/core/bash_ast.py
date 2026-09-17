"""Bash AST parsing powered by bashlex."""

from __future__ import annotations

import contextlib
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

import bashlex
import bashlex.ast
import bashlex.errors

# bashlex raises these on input it cannot parse. Callers deliberately fall back to a
# naive word split rather than failing the command: an unparseable line must still be
# classified by the terminal policy gate, because a parse error is not a safe default.
_BASH_PARSE_ERRORS: tuple[type[BaseException], ...] = (bashlex.errors.ParsingError,)

# Interpreters whose -c / -e argument is a nested script whose tokens are
# executed and therefore ARE connection targets (unlike quoted text labels).
_INTERPRETER_CODE_FLAGS: dict[str, tuple[str, ...]] = {
    "bash": ("-c",),
    "sh": ("-c",),
    "zsh": ("-c",),
    "dash": ("-c",),
    "ksh": ("-c",),
    "python": ("-c", "-e"),
    "python3": ("-c", "-e"),
    "python2": ("-c", "-e"),
    "node": ("-e",),
    "perl": ("-e",),
    "ruby": ("-e",),
    "php": ("-r",),
    "awk": ("-f",),
}


@dataclass
class CommandSegment:
    raw_text: str
    words: list[str] = field(default_factory=list)
    executable: str = ""
    redirects: list[str] = field(default_factory=list)


# A here-document redirect (<<[-]TAG ... TAG). bashlex cannot parse heredoc
# bodies (it raises "here-document ... delimited by end-of-file"), so callers
# fall back to naive whitespace splitting — where URLs and host literals in
# the *payload text* are misread as connection targets. Match the redirect
# operator + tag on a logical first line; the body follows on later lines.
_HEREDOC_RE = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")


def split_heredoc_body(command: str) -> tuple[str, str | None]:
    """Split a command into (executable text, heredoc body) when it carries one.

    The returned executable text keeps the redirect operator and tag but drops
    the body, so downstream tokenizers never see payload text as executed
    tokens. Returns (command, None) when no heredoc is present or the body is
    unterminated (caller keeps the original so nothing silently whitelists).
    """
    match = _HEREDOC_RE.search(command)
    if not match:
        return command, None
    # Only a redirect on the first logical line opens a heredoc body.
    if "\n" in command[: match.start()]:
        return command, None
    tag = match.group("tag")
    body_start = command.find("\n", match.end())
    if body_start == -1:
        return command, None
    body = command[body_start + 1 :]
    end_re = re.compile(rf"^[ \t]*{re.escape(tag)}[ \t]*$", re.MULTILINE)
    end = end_re.search(body)
    if not end:
        return command, None
    body_text = body[: end.start()]
    remainder = body[end.end() :]
    # Keep an empty, terminated heredoc so bashlex can still parse commands
    # following the payload. An unterminated redirect consumed the remainder.
    head = command[: match.end()] + "\n" + tag + "\n" + remainder.lstrip("\n")
    return head.strip("\n"), body_text


class _WordCollector(bashlex.ast.nodevisitor):
    """Collect word and redirect target tokens from an AST subtree."""

    def __init__(self) -> None:
        self.words: list[str] = []

    def visitword(self, n: Any, word: str) -> None:
        self.words.append(word)

    def visitredirect(self, n: Any, input: Any, type: str, output: Any, heredoc: Any) -> None:
        if hasattr(output, "word"):
            self.words.append(output.word)


class _CommandVisitor(bashlex.ast.nodevisitor):
    """Traverse bashlex AST nodes to extract command segments and word tokens."""

    def __init__(self, command: str):
        self.command = command
        self.segments: list[CommandSegment] = []
        self.words: list[str] = []

    def visitcommand(self, node: Any, parts: list[Any]) -> None:
        start, end = node.pos
        segment_text = self.command[start:end]

        collector = _WordCollector()
        for part in parts:
            collector.visit(part)
        words = collector.words
        self.words.extend(words)

        executable = self._extract_executable(words)
        redirects = [
            str(part.output.word)
            for part in parts
            if getattr(part, "kind", None) == "redirect"
            and hasattr(getattr(part, "output", None), "word")
        ]
        self.segments.append(
            CommandSegment(
                raw_text=segment_text,
                words=words,
                executable=executable,
                redirects=redirects,
            )
        )
        self._visit_interpreter_code(words, executable)

    def _visit_interpreter_code(self, words: list[str], executable: str) -> None:
        """Recurse into interpreter -c / -e arguments so their executed
        tokens (e.g. /dev/tcp/...) are still treated as connection targets,
        while quoted text labels (echo '=== SSRF 1.2.3.4 ===') stay atomic.
        Only words are collected — no nested CommandSegments are appended."""
        for flag in _INTERPRETER_CODE_FLAGS.get(executable, ()):
            if flag in words:
                idx = words.index(flag)
                if idx + 1 < len(words):
                    code = words[idx + 1].strip()
                    if code:
                        with contextlib.suppress(_BASH_PARSE_ERRORS):
                            collector = _WordCollector()
                            for child in bashlex.parse(code):
                                collector.visit(child)
                            self.words.extend(collector.words)
                break

    @staticmethod
    def _extract_executable(words: list[str]) -> str:
        for word in words:
            if "=" in word and not word.startswith("-") and not word.startswith("/"):
                continue
            if word.lower() in {"command", "env", "exec", "nice", "sudo", "timeout"}:
                continue
            return word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        return ""


def parse_bash_segments(command: str) -> list[CommandSegment]:
    """Parse shell command into AST segments using bashlex.

    Heredoc bodies are stripped before parsing: bashlex cannot parse
    here-documents (it raises "here-document ... delimited by end-of-file"),
    which would otherwise drop the caller into the naive whitespace-split
    fallback where payload URLs are misread as connection targets.
    """
    if not command or not command.strip():
        return []
    if _HEREDOC_RE.search(command):
        command, _body = split_heredoc_body(command)

    with contextlib.suppress(_BASH_PARSE_ERRORS):
        nodes = bashlex.parse(command)
        visitor = _CommandVisitor(command)
        for node in nodes:
            visitor.visit(node)
        if visitor.segments:
            return visitor.segments

    words = command.split()
    exec_name = _CommandVisitor._extract_executable(words)
    return [CommandSegment(raw_text=command, words=words, executable=exec_name)]


def extract_all_command_words(command: str) -> list[str]:
    """Extract all word tokens across subcommands, pipelines, and subshells via bashlex AST."""
    if not command or not command.strip():
        return []
    if _HEREDOC_RE.search(command):
        command, _body = split_heredoc_body(command)

    with contextlib.suppress(_BASH_PARSE_ERRORS):
        nodes = bashlex.parse(command)
        visitor = _CommandVisitor(command)
        for node in nodes:
            visitor.visit(node)
        if visitor.words:
            all_words: list[str] = []
            for word in visitor.words:
                cleaned = word.strip("'\"`")
                if cleaned:
                    all_words.append(cleaned)
                    # Split only on shell operator characters, never on plain
                    # spaces: quoted text labels ("echo '=== SSRF 1.2.3.4 ==='")
                    # must stay one word, or bare IPs inside labels become
                    # false-positive connection targets.
                    if any(char in cleaned for char in (";", "|", "&", ">", "<")):
                        for sub in re.split(r"[;|&><]+", cleaned):
                            sub_clean = sub.strip("'\"` \t")
                            if sub_clean:
                                all_words.append(sub_clean)
            return list(dict.fromkeys(all_words))

    try:
        return list(dict.fromkeys(shlex.split(command, posix=True)))
    except ValueError:
        return list(dict.fromkeys(command.split()))
