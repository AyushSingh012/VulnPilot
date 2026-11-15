"""Apply upgrades to a Poetry project, to the exact target version.

Poetry has no ``uv lock --upgrade-package pkg==ver``, and ``poetry update pkg`` jumps to the
newest version the range allows. Instead, each target is pinned in a temporary dependency
group, the project is locked, the group is removed and the project is locked again.
``poetry lock`` keeps already-locked versions, so the pinned versions stay and
pyproject.toml ends up with only the bound edits a direct dependency needed. If a parent's
locked version blocks a pin, Poetry moves that parent forward itself; that is reported as a
parent upgrade.
"""

from __future__ import annotations

import re
from pathlib import Path

import tomlkit

from vulnpilot import proc
from vulnpilot.fixers.base import LockError
from vulnpilot.lockgraph import LockGraph, lock_versions
from vulnpilot.models import Upgrade, normalize_package
from vulnpilot.proc import ToolNotFoundError, ToolTimeoutError
from vulnpilot.specifiers import SpecifierEditError, raise_to

LOCK_TIMEOUT_S = 600
PIN_GROUP = "vulnpilot-pin"


def _last_lines(text: str, n: int = 4) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return " ".join(lines[-n:]) if lines else "no output"


def poetry_major(env: dict[str, str] | None = None) -> int:
    """Major version of the installed Poetry (2 when it cannot be told)."""
    try:
        result = proc.run(["poetry", "--version"], timeout=60, env=env)
    except (ToolNotFoundError, ToolTimeoutError) as exc:
        raise LockError("poetry is not installed; it is needed for Poetry projects") from exc
    match = re.search(r"(\d+)\.\d+", result.stdout + result.stderr)
    return int(match.group(1)) if match else 2


def with_pins(pyproject_text: str, pins: dict[str, str]) -> str:
    doc = tomlkit.parse(pyproject_text)
    tool = doc.setdefault("tool", tomlkit.table(is_super_table=True))
    poetry = tool.setdefault("poetry", tomlkit.table())
    groups = poetry.setdefault("group", tomlkit.table(is_super_table=True))
    deps = tomlkit.table()
    for package, version in pins.items():
        deps[package] = f"=={version}"
    group = tomlkit.table()
    group["dependencies"] = deps
    groups[PIN_GROUP] = group
    return tomlkit.dumps(doc)


class PoetryFixer:
    def __init__(self, project_dir: Path, graph: LockGraph, env: dict[str, str]) -> None:
        self.project_dir = project_dir
        self.pyproject = project_dir / "pyproject.toml"
        self.lockfile = project_dir / "poetry.lock"
        self.graph = graph
        self.env = {**env, "POETRY_NO_INTERACTION": "1"}
        self._orig_pyproject = self.pyproject.read_bytes()
        self._orig_lock = self.lockfile.read_bytes()
        self._orig_versions = lock_versions(self.lockfile)
        # Poetry 1.x re-resolves everything on `poetry lock` unless told not to.
        self._lock_cmd = ["poetry", "lock"]
        if poetry_major(self.env) < 2:
            self._lock_cmd.append("--no-update")
        self.pyproject_changes: dict[str, list[tuple[str, str]]] = {}
        self.resolver_errors: dict[str, str] = {}
        """package -> Poetry's full message, written to the run log."""

    def restore(self) -> None:
        self.pyproject.write_bytes(self._orig_pyproject)
        self.lockfile.write_bytes(self._orig_lock)

    def _lock(self) -> None:
        try:
            result = proc.run(
                self._lock_cmd, cwd=self.project_dir, timeout=LOCK_TIMEOUT_S, env=self.env
            )
        except ToolTimeoutError as exc:
            raise LockError(f"poetry lock timed out after {LOCK_TIMEOUT_S}s") from exc
        if not result.ok:
            raise LockError(_last_lines(result.stderr or result.stdout))

    def apply(self, upgrades: list[Upgrade]) -> None:
        self.restore()
        if not upgrades:
            return
        text = self._orig_pyproject.decode("utf-8")
        for u in upgrades:
            if u.method == "raise-bound":
                try:
                    text, changes = raise_to(text, u.package, u.to_version)
                except SpecifierEditError as exc:
                    raise LockError(str(exc)) from exc
                self.pyproject_changes[u.package] = changes
        try:
            pins = {u.package: u.to_version for u in upgrades}
            self.pyproject.write_text(with_pins(text, pins), encoding="utf-8")
            self._lock()
            self.pyproject.write_text(text, encoding="utf-8")
            self._lock()
            locked = lock_versions(self.lockfile)
            for u in upgrades:
                got = locked.get(normalize_package(u.package))
                if got != u.to_version:
                    raise LockError(f"{u.package} did not stay at {u.to_version} (got {got})")
        except LockError:
            self.restore()
            raise

    def _direct_parents(self, package: str) -> list[str]:
        return sorted({path[1] for path in self.graph.paths_to(package) if len(path) > 2})

    def _moved_parents(self, package: str) -> list[str]:
        now = lock_versions(self.lockfile)
        return [
            p for p in self._direct_parents(package) if now.get(p) != self._orig_versions.get(p)
        ]

    def resolve_each(self, upgrades: list[Upgrade]) -> tuple[list[Upgrade], dict[str, str]]:
        accepted: list[Upgrade] = []
        blocked: dict[str, str] = {}
        for u in upgrades:
            try:
                self.apply([*accepted, u])
            except LockError as exc:
                self.resolver_errors[u.package] = str(exc)
                parents = self._direct_parents(u.package)
                if parents and not self.graph.is_direct(u.package):
                    blocked[u.package] = (
                        f"{', '.join(parents)} does not allow {u.package} {u.to_version}, "
                        "even at its newest version"
                    )
                else:
                    blocked[u.package] = f"Poetry could not resolve {u.package} {u.to_version}"
                continue
            moved = [] if self.graph.is_direct(u.package) else self._moved_parents(u.package)
            if moved:
                u = u.model_copy(update={"method": "parent-upgrade", "parents": moved})
            accepted.append(u)
        self.restore()
        return accepted, blocked

    def locked_version(self, package: str) -> str | None:
        return lock_versions(self.lockfile).get(normalize_package(package))
