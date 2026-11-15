"""Find the project, its package manager and lockfile."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from vulnpilot import proc
from vulnpilot.models import Project
from vulnpilot.proc import ToolNotFoundError


class DetectError(Exception):
    """The path is not a Python project VulnPilot v1 can work on."""


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise DetectError(f"{path} is not valid TOML: {exc}") from exc


def project_name(pyproject: dict[str, Any]) -> str | None:
    name = pyproject.get("project", {}).get("name")
    if name is None:
        name = pyproject.get("tool", {}).get("poetry", {}).get("name")
    return str(name) if name else None


def _is_uv_workspace(pyproject: dict[str, Any], lockfile: Path) -> bool:
    if "workspace" in pyproject.get("tool", {}).get("uv", {}):
        return True
    members = _read_toml(lockfile).get("manifest", {}).get("members", [])
    return len(members) > 1


def _commit_sha(root: Path) -> str | None:
    try:
        result = proc.run(["git", "rev-parse", "HEAD"], cwd=root, timeout=10)
    except ToolNotFoundError:
        return None
    return result.stdout.strip() if result.ok else None


def detect_project(path: Path, base_branch: str = "main") -> Project:
    root = path.resolve()
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        raise DetectError(f"no pyproject.toml in {root}")
    pyproject = _read_toml(pyproject_path)

    uv_lock = root / "uv.lock"
    poetry_lock = root / "poetry.lock"
    if uv_lock.is_file():
        if _is_uv_workspace(pyproject, uv_lock):
            raise DetectError(
                f"{root} is a uv workspace (several projects, one uv.lock); "
                "workspaces are not supported in v1"
            )
        manager, lockfile = "uv", uv_lock
    elif poetry_lock.is_file():
        manager, lockfile = "poetry", poetry_lock
    else:
        raise DetectError(
            f"no uv.lock or poetry.lock in {root}; run `uv lock` or `poetry lock` first"
        )

    return Project(
        root=root,
        manager=manager,
        lockfile=lockfile,
        commit_sha=_commit_sha(root),
        base_branch=base_branch,
    )
