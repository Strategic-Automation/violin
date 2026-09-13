"""Shared result base classes for the Violin Guard core library."""

from __future__ import annotations

from dataclasses import dataclass, field


def _is_advisory_hint(message: str) -> bool:
    """Return True if message is an advisory hint rather than a blocking review requirement."""
    normalized = message.lower()
    return (
        "hint" in normalized
        or "not a block" in normalized
        or "execution still allowed" in normalized
    )


@dataclass
class GuardResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def add_info(self, msg: str) -> None:
        self.infos.append(msg)

    def add_hint(self, msg: str) -> None:
        self.warnings.append(msg)

    def exit_code(self) -> int:
        if self.errors:
            return 1
        blocking_warnings = [warning for warning in self.warnings if not _is_advisory_hint(warning)]
        if blocking_warnings:
            return 2
        return 0
