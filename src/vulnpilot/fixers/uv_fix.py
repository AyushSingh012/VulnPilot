"""Apply upgrades to a uv project: pyproject.toml specifier edits + `uv lock -P pkg==ver`."""

from __future__ import annotations

import tomllib
from pathlib import Path

from vulnpilot import proc
from vulnpilot.fixers.base import LockError
from vulnpilot.lockgraph import LockGraph
from vulnpilot.models import Upgrade, normalize_package
from vulnpilot.proc import ToolTimeoutError
from vulnpilot.specifiers import SpecifierEditError, raise_to

LOCK_TIMEOUT_S = 300


def _last_lines(text: str, n: int = 4) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return " ".join(lines[-n:]) if lines else "no output"


class UvFixer:
    def __init__(self, project_dir: Path, graph: LockGraph, env: dict[str, str]) -> None:
        self.project_dir = project_dir
        self.pyproject = project_dir / "pyproject.toml"
        self.lockfile = project_dir / "uv.lock"
        self.graph = graph
        self.env = env
        self._orig_pyproject = self.pyproject.read_bytes()
        self._orig_lock = self.lockfile.read_bytes()
        self.pyproject_changes: dict[str, list[tuple[str, str]]] = {}
        self.resolver_errors: dict[str, str] = {}
        """package -> uv's full message, written to the run log."""

    def restore(self) -> None:
        self.pyproject.write_bytes(self._orig_pyproject)
        self.lockfile.write_bytes(self._orig_lock)

    def _lock(self, upgrades: list[Upgrade]) -> None:
        cmd = ["uv", "lock"]
        for u in upgrades:
            cmd += ["--upgrade-package", f"{u.package}=={u.to_version}"]
            for parent in u.parents:
                cmd += ["--upgrade-package", parent]
        try:
            result = proc.run(cmd, cwd=self.project_dir, timeout=LOCK_TIMEOUT_S, env=self.env)
        except ToolTimeoutError as exc:
            raise LockError(f"uv lock timed out after {LOCK_TIMEOUT_S}s") from exc
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
        self.pyproject.write_text(text, encoding="utf-8")
        try:
            self._lock(upgrades)
        except LockError:
            self.restore()
            raise

    def _direct_parents(self, package: str) -> list[str]:
        return sorted({path[1] for path in self.graph.paths_to(package) if len(path) > 2})

    def resolve_each(self, upgrades: list[Upgrade]) -> tuple[list[Upgrade], dict[str, str]]:
        accepted: list[Upgrade] = []
        blocked: dict[str, str] = {}
        for u in upgrades:
            try:
                self.apply([*accepted, u])
                accepted.append(u)
                continue
            except LockError as exc:
                first_error = str(exc)
            parents = self._direct_parents(u.package)
            if not self.graph.is_direct(u.package) and parents:
                lifted = u.model_copy(update={"method": "parent-upgrade", "parents": parents})
                try:
                    self.apply([*accepted, lifted])
                    accepted.append(lifted)
                    continue
                except LockError:
                    pass
            self.resolver_errors[u.package] = first_error
            if parents:
                blocked[u.package] = (
                    f"{', '.join(parents)} does not allow {u.package} {u.to_version}, "
                    "even at its newest version"
                )
            else:
                blocked[u.package] = f"uv could not resolve {u.package} {u.to_version}"
        self.restore()
        return accepted, blocked

    def locked_version(self, package: str) -> str | None:
        data = tomllib.loads(self.lockfile.read_text(encoding="utf-8"))
        name = normalize_package(package)
        for pkg in data.get("package", []):
            if normalize_package(pkg["name"]) == name:
                return str(pkg.get("version")) if pkg.get("version") else None
        return None
