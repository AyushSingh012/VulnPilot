"""Temporary git worktree from origin/<base_branch>: the developer's checkout is never touched."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from vulnpilot import proc
from vulnpilot.proc import ProcResult

# Files tools may create while installing / testing; never counted as changes.
_TOOL_DIRS = {".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox"}
_TOOL_SUFFIXES = (".pyc", ".egg-info", ".egg-info/")


class WorktreeError(Exception):
    """git could not prepare or clean up the worktree."""


@dataclass(frozen=True)
class Worktree:
    repo_root: Path
    path: Path
    project_dir: Path
    """The project inside the worktree (repos can hold the project in a subfolder)."""
    project_rel: str
    """Project folder relative to the repo root, '' for the root itself."""
    ref: str
    commit_sha: str


def git(args: list[str], cwd: Path, timeout: float = 120) -> ProcResult:
    return proc.run(["git", *args], cwd=cwd, timeout=timeout)


def _must(result: ProcResult, what: str) -> str:
    if not result.ok:
        detail = (result.stderr.strip().splitlines() or ["no output"])[-1]
        raise WorktreeError(f"{what}: {detail}")
    return result.stdout.strip()


def _base_ref(repo: Path, base_branch: str) -> str:
    remotes = _must(git(["remote"], repo), "git remote").split()
    if "origin" in remotes:
        _must(
            git(["fetch", "--quiet", "origin", base_branch], repo, timeout=300),
            (f"could not fetch origin/{base_branch}"),
        )
        return f"origin/{base_branch}"
    _must(
        git(["rev-parse", "--verify", "--quiet", base_branch], repo),
        (f"no 'origin' remote and no local branch '{base_branch}'"),
    )
    return base_branch


@contextmanager
def worktree(
    project_root: Path, base_branch: str, dest: Path, keep: bool = False
) -> Iterator[Worktree]:
    top = git(["rev-parse", "--show-toplevel"], project_root)
    if not top.ok:
        raise WorktreeError(f"{project_root} is not inside a git repository")
    repo = Path(top.stdout.strip()).resolve()
    rel = project_root.resolve().relative_to(repo)
    ref = _base_ref(repo, base_branch)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _must(
        git(["worktree", "add", "--detach", "--quiet", str(dest), ref], repo),
        (f"could not create a worktree from {ref}"),
    )
    try:
        sha = _must(git(["rev-parse", "HEAD"], dest), "git rev-parse")
        project_dir = dest / rel
        if not (project_dir / "pyproject.toml").is_file():
            raise WorktreeError(f"{rel.as_posix() or '.'} has no pyproject.toml on {ref}")
        yield Worktree(repo, dest, project_dir, rel.as_posix().strip("."), ref, sha)
    finally:
        if not keep:
            removed = git(["worktree", "remove", "--force", str(dest)], repo)
            if not removed.ok:
                shutil.rmtree(dest, ignore_errors=True)
                git(["worktree", "prune"], repo)


def _is_tool_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(p in _TOOL_DIRS for p in parts) or path.endswith(_TOOL_SUFFIXES)


def changed_files(wt: Worktree) -> list[str]:
    """Tracked changes plus new files git does not ignore, relative to the repo root."""
    result = git(["status", "--porcelain", "--untracked-files=all"], wt.path)
    _must(result, "git status")
    # Porcelain lines are "XY <path>": two status columns, a space, then the path.
    files = [line[3:].strip().strip('"') for line in result.stdout.splitlines() if len(line) > 3]
    return sorted(f for f in files if not _is_tool_file(f))


def allowed_files(wt: Worktree, lockfile_name: str) -> set[str]:
    prefix = f"{wt.project_rel}/" if wt.project_rel else ""
    return {f"{prefix}pyproject.toml", f"{prefix}{lockfile_name}"}
