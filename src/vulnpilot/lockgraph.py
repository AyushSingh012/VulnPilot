"""Dependency graph of a project: which packages are direct, and how others are pulled in."""

from __future__ import annotations

import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from vulnpilot.detect import project_name
from vulnpilot.models import Project, normalize_package

MAX_PATHS = 5


@dataclass
class LockGraph:
    root: str
    edges: dict[str, set[str]] = field(default_factory=dict)
    """package -> packages it depends on (normalized names)."""
    direct: set[str] = field(default_factory=set)
    """Runtime direct dependencies of the project (incl. optional extras)."""
    direct_dev: set[str] = field(default_factory=set)
    """Direct dependencies that come only from dependency groups (dev)."""

    def is_direct(self, package: str) -> bool:
        name = normalize_package(package)
        return name in self.direct or name in self.direct_dev

    def _reachable(self, starts: set[str]) -> set[str]:
        seen: set[str] = set()
        queue = deque(starts)
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(self.edges.get(node, ()))
        return seen

    def is_dev_only(self, package: str) -> bool:
        name = normalize_package(package)
        return name not in self._reachable(self.direct) and name in self._reachable(self.direct_dev)

    def paths_to(self, package: str) -> list[list[str]]:
        """Shortest path from the project to ``package`` through each direct dependency."""
        target = normalize_package(package)
        paths: list[list[str]] = []
        for first in sorted(self.direct | self.direct_dev):
            path = self._shortest(first, target)
            if path is not None:
                paths.append([self.root, *path])
        paths.sort(key=len)
        return paths[:MAX_PATHS]

    def _shortest(self, start: str, target: str) -> list[str] | None:
        queue: deque[list[str]] = deque([[start]])
        seen = {start}
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == target:
                return path
            for nxt in sorted(self.edges.get(node, ())):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append([*path, nxt])
        return None


def _names(entries: list[dict[str, Any]]) -> set[str]:
    return {normalize_package(e["name"]) for e in entries}


def load_uv_graph(lockfile: Path, root_name: str) -> LockGraph:
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    root = normalize_package(root_name)
    graph = LockGraph(root=root)
    for pkg in data.get("package", []):
        name = normalize_package(pkg["name"])
        deps = _names(pkg.get("dependencies", []))
        for extra in pkg.get("optional-dependencies", {}).values():
            deps |= _names(extra)
        if name == root:
            graph.direct |= deps
            for group in pkg.get("dev-dependencies", {}).values():
                graph.direct_dev |= _names(group)
        graph.edges.setdefault(name, set()).update(deps)
    graph.direct_dev -= graph.direct
    graph.edges[root] = graph.direct | graph.direct_dev
    return graph


def _requirement_names(specs: list[str]) -> set[str]:
    names: set[str] = set()
    for spec in specs:
        try:
            names.add(normalize_package(Requirement(spec).name))
        except InvalidRequirement:
            continue
    return names


def load_poetry_graph(pyproject: dict[str, Any], root_name: str) -> LockGraph:
    """v1 reads only which packages are direct for Poetry; paths come in Stage 6."""
    graph = LockGraph(root=normalize_package(root_name))
    graph.direct |= _requirement_names(pyproject.get("project", {}).get("dependencies", []))
    poetry = pyproject.get("tool", {}).get("poetry", {})
    graph.direct |= {normalize_package(n) for n in poetry.get("dependencies", {}) if n != "python"}
    for group in poetry.get("group", {}).values():
        graph.direct_dev |= {normalize_package(n) for n in group.get("dependencies", {})}
    graph.direct_dev -= graph.direct
    return graph


def load_graph(project: Project) -> LockGraph:
    pyproject = tomllib.loads((project.root / "pyproject.toml").read_text(encoding="utf-8"))
    name = project_name(pyproject) or project.root.name
    if project.manager == "uv":
        return load_uv_graph(project.lockfile, name)
    return load_poetry_graph(pyproject, name)
