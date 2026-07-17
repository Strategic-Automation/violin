"""Shared result base classes for the Violin Guard core library."""

from __future__ import annotations

from dataclasses import dataclass, field


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

    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0
