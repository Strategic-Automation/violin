"""Source-positioned Markdown block structure used by guard documents."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from markdown_it import MarkdownIt


@dataclass(frozen=True)
class MarkdownBlock:
    """One structural block mapped back to its original source lines."""

    kind: str
    start: int
    end: int
    level: int = 0
    text: str = ""


def iter_markdown_blocks(source: str) -> Iterator[MarkdownBlock]:
    """Yield headings, tables, and protected blocks with source line ranges.

    Parser maps are half-open line ranges. The parser normalizes newline spelling
    internally, but line indexes remain usable against ``source.splitlines()``; callers
    must splice the original text rather than render these tokens back to Markdown.
    """

    parser = MarkdownIt("commonmark", {"html": True}).enable("table")
    tokens = parser.parse(source)
    for index, token in enumerate(tokens):
        if token.map is None or len(token.map) != 2:
            continue
        start, end = int(token.map[0]), int(token.map[1])
        if token.type == "heading_open" and token.level == 0:
            inline = tokens[index + 1] if index + 1 < len(tokens) else None
            if inline is not None and inline.type == "inline":
                yield MarkdownBlock(
                    "heading", start, end, int(token.tag.removeprefix("h")), inline.content.strip()
                )
        elif token.type == "table_open" and token.level == 0:
            yield MarkdownBlock("table", start, end)
        elif token.type in {"fence", "code_block", "html_block"}:
            yield MarkdownBlock("protected", start, end)
        elif token.type == "inline" and any(
            child.type == "html_inline" for child in token.children or ()
        ):
            # Inline HTML comments have no independent block token. Protect their
            # containing source line so comment examples cannot become records.
            yield MarkdownBlock("protected", start, end)


def read_markdown(path: Path) -> str:
    """Read UTF-8 Markdown without universal-newline conversion."""
    with path.open("r", encoding="utf-8", newline="") as source_file:
        return source_file.read()
