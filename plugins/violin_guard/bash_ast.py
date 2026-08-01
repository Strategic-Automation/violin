"""Bash AST parsing powered by bashlex."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any

import bashlex


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

        if hasattr(node, "parts"):
            for child in node.parts:
                self.visit(child)
        if hasattr(node, "command") and getattr(node, "command", None):
            self.visit(node.command)
        if hasattr(node, "list") and getattr(node, "list", None):
            for item in getattr(node, "list", []):
                self.visit(item)

    def _collect_words(self, node: Any) -> list[str]:
        words: list[str] = []

        def collect(n):
            kind = getattr(n, "kind", None)
            if kind == "word" and hasattr(n, "word"):
                words.append(n.word)
                self.words.append(n.word)
            elif kind == "redirect":
                output = getattr(n, "output", None)
                if output is not None and hasattr(output, "word"):
                    words.append(output.word)
                    self.words.append(output.word)
            if hasattr(n, "parts"):
                for child in n.parts:
                    collect(child)
            if hasattr(n, "command") and getattr(n, "command", None):
                collect(n.command)
            if hasattr(n, "list") and getattr(n, "list", None):
                for item in getattr(n, "list", []):
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
            for w in visitor.words:
                cleaned = w.strip("'\"`")
                if cleaned:
                    all_words.append(cleaned)
                    if any(char in cleaned for char in (" ", ";", "|", "&", ">", "<")):
                        for sub in cleaned.replace(";", " ").replace("|", " ").split():
                            sub_clean = sub.strip("'\"`")
                            if sub_clean:
                                all_words.append(sub_clean)
            return list(dict.fromkeys(all_words))
    except Exception:
        pass

    try:
        return list(dict.fromkeys(shlex.split(command, posix=True)))
    except ValueError:
        return list(dict.fromkeys(command.split()))
