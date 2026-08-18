"""Bash AST parsing powered by bashlex."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any

import bashlex

# Interpreters whose -c / -e argument is a nested script whose tokens are
# executed and therefore ARE connection targets (unlike quoted text labels).
_INTERPRETER_CODE_FLAGS = {
    "bash": "-c",
    "sh": "-c",
    "zsh": "-c",
    "dash": "-c",
    "ksh": "-c",
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


class _CommandVisitor:
    """Traverse bashlex AST nodes to extract command segments and word tokens."""

    def __init__(self, command: str):
        self.command = command
        self.segments: list[CommandSegment] = []
        self.words: list[str] = []

    def visit(self, node: Any) -> None:
        kind = getattr(node, "kind", None)
        if kind == "command":
            start, end = node.pos
            segment_text = self.command[start:end]
            words = self._collect_words(node)
            executable = self._extract_executable(words)
            redirects = [
                str(getattr(getattr(part, "output", None), "word", ""))
                for part in getattr(node, "parts", [])
                if getattr(part, "kind", None) == "redirect"
                and getattr(getattr(part, "output", None), "word", None)
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

        if hasattr(node, "parts"):
            for child in node.parts:
                self.visit(child)
        if hasattr(node, "command") and getattr(node, "command", None):
            self.visit(node.command)
        if hasattr(node, "list") and getattr(node, "list", None):
            for item in getattr(node, "list", []):
                self.visit(item)

    def _visit_interpreter_code(self, words: list[str], executable: str) -> None:
        """Recurse into interpreter -c / -e arguments so their executed
        tokens (e.g. /dev/tcp/...) are still treated as connection targets,
        while quoted text labels (echo '=== SSRF 1.2.3.4 ===') stay atomic.
        Only words are collected — no nested CommandSegments are appended."""
        flags = _INTERPRETER_CODE_FLAGS.get(executable)
        if not flags:
            return
        if isinstance(flags, str):
            candidates = [flags]
        else:
            candidates = [flag for flag in flags if flag in words]
        if not candidates:
            return
        flag = candidates[0]
        try:
            code = words[words.index(flag) + 1]
        except IndexError:
            return
        if not code.strip():
            return
        try:
            nested = bashlex.parse(code)
        except Exception:
            return
        for child in nested:
            self._collect_words(child)

    def _collect_words(self, node: Any) -> list[str]:
        words: list[str] = []

        def collect(ast_node):
            kind = getattr(ast_node, "kind", None)
            if kind == "word" and hasattr(ast_node, "word"):
                words.append(ast_node.word)
                self.words.append(ast_node.word)
            elif kind == "redirect":
                output = getattr(ast_node, "output", None)
                if output is not None and hasattr(output, "word"):
                    words.append(output.word)
                    self.words.append(output.word)
            if hasattr(ast_node, "parts"):
                for child in ast_node.parts:
                    collect(child)
            if hasattr(ast_node, "command") and getattr(ast_node, "command", None):
                collect(ast_node.command)
            if hasattr(ast_node, "list") and getattr(ast_node, "list", None):
                for item in getattr(ast_node, "list", []):
                    collect(item)

        collect(node)
        return words

    @staticmethod
    def _extract_executable(words: list[str]) -> str:
        for word in words:
            if "=" in word and not word.startswith("-") and not word.startswith("/"):
                continue
            if word.lower() in {"command", "env", "exec", "nice", "sudo", "timeout"}:
                continue
            base = word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            return base
        return ""


def parse_bash_segments(command: str) -> list[CommandSegment]:
    """Parse shell command into AST segments using bashlex."""
    if not command or not command.strip():
        return []
    try:
        nodes = bashlex.parse(command)
        visitor = _CommandVisitor(command)
        for node in nodes:
            visitor.visit(node)
        if visitor.segments:
            return visitor.segments
    except Exception:
        pass

    words = command.split()
    exec_name = _CommandVisitor._extract_executable(words)
    return [CommandSegment(raw_text=command, words=words, executable=exec_name)]


def extract_all_command_words(command: str) -> list[str]:
    """Extract all word tokens across subcommands, pipelines, and subshells via bashlex AST."""
    if not command or not command.strip():
        return []
    try:
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
    except Exception:
        pass

    try:
        return list(dict.fromkeys(shlex.split(command, posix=True)))
    except ValueError:
        return list(dict.fromkeys(command.split()))
