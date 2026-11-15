from __future__ import annotations

from typing import Protocol

from vulnpilot.models import Upgrade


class LockError(Exception):
    """The resolver could not satisfy the requested upgrades."""


class Fixer(Protocol):
    """UvFixer and PoetryFixer."""

    def restore(self) -> None:
        """Put pyproject.toml and the lockfile back as they were on the base branch."""
        ...

    def apply(self, upgrades: list[Upgrade]) -> None:
        """Start from the original files and apply exactly ``upgrades``; raise LockError."""
        ...

    def resolve_each(self, upgrades: list[Upgrade]) -> tuple[list[Upgrade], dict[str, str]]:
        """Add upgrades one at a time; return those that resolve together and why others don't."""
        ...

    def locked_version(self, package: str) -> str | None: ...
