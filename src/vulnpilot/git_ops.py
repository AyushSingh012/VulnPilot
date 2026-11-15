"""Commit, branch and push for the one VulnPilot PR.

The PR branch is rebuilt from the base commit on every run: one commit, holding only
pyproject.toml and the lockfile. Every VulnPilot commit carries a ``VulnPilot-Run:``
trailer; a branch holding any other non-merge commit belongs to a human, and VulnPilot
refuses to overwrite it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from vulnpilot import proc
from vulnpilot.proc import ProcResult, ToolNotFoundError, ToolTimeoutError

TRAILER = "VulnPilot-Run"

# git@host:owner/repo(.git) · ssh://git@host[:port]/owner/repo · https://host/owner/repo
_REMOTE_RE = re.compile(
    r"^(?:(?:ssh|https?|git)://)?(?:[^@/\s]+@)?"
    r"(?P<host>[\w.-]+)(?::\d+)?[:/](?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)


class GitError(Exception):
    """A git step failed; the message says which and why."""


@dataclass(frozen=True)
class BranchState:
    """Where the PR branch stands before this run changes anything."""

    name: str
    sha: str | None
    """Its current commit, or None if the branch does not exist."""
    foreign: list[str]
    """Short SHAs of commits on it that VulnPilot did not make."""


def git(args: list[str], cwd: Path, *, env: dict[str, str] | None = None) -> ProcResult:
    full_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})}
    try:
        return proc.run(["git", *args], cwd=cwd, timeout=300, env=full_env)
    except ToolNotFoundError as exc:
        raise GitError("git is not installed") from exc
    except ToolTimeoutError as exc:
        raise GitError(f"git {args[0]} timed out") from exc


def _must(result: ProcResult, what: str) -> str:
    if not result.ok:
        lines = [ln for ln in result.stderr.strip().splitlines() if ln.strip()]
        raise GitError(f"{what}: {lines[-1] if lines else f'exit code {result.returncode}'}")
    return result.stdout.strip()


def repo_slug(repo: Path, remote: str = "origin") -> str:
    """``owner/name`` of the GitHub repo behind ``remote`` (SSH host aliases are fine)."""
    url = _must(git(["remote", "get-url", remote], repo), f"no '{remote}' remote")
    match = _REMOTE_RE.match(url.strip())
    if not match:
        raise GitError(f"cannot read a GitHub owner/repo from the '{remote}' remote URL")
    return f"{match['owner']}/{match['repo']}"


def has_remote(repo: Path, remote: str = "origin") -> bool:
    return remote in _must(git(["remote"], repo), "git remote").split()


def remote_branch_sha(repo: Path, branch: str, env: dict[str, str] | None = None) -> str | None:
    out = _must(
        git(["ls-remote", "--heads", "origin", f"refs/heads/{branch}"], repo, env=env),
        "could not read branches from origin",
    )
    return out.split()[0] if out else None


def local_branch_sha(repo: Path, branch: str) -> str | None:
    result = git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}"], repo)
    return result.stdout.strip() if result.ok else None


def foreign_commits(repo: Path, base: str, tip: str) -> list[str]:
    """Non-merge commits in base..tip without the VulnPilot trailer.

    Merge commits are allowed (GitHub's "Update branch" makes them); they only bring in
    base commits, and the rebuild drops them anyway.
    """
    out = _must(
        git(
            [
                "log",
                "--no-merges",
                f"--format=%h %(trailers:key={TRAILER},valueonly,separator=%x2C)",
                f"{base}..{tip}",
            ],
            repo,
        ),
        "could not read the PR branch history",
    )
    return [line.split()[0] for line in out.splitlines() if len(line.split()) < 2]


def branch_state(
    repo: Path, branch: str, base_sha: str, *, remote: bool, env: dict[str, str] | None = None
) -> BranchState:
    """The PR branch on origin (``remote``) or in the local repo, and any foreign commits."""
    if remote:
        sha = remote_branch_sha(repo, branch, env)
        if sha:
            _must(
                git(["fetch", "--quiet", "origin", f"refs/heads/{branch}"], repo, env=env),
                f"could not fetch {branch}",
            )
    else:
        sha = local_branch_sha(repo, branch)
    foreign = foreign_commits(repo, base_sha, sha) if sha else []
    return BranchState(branch, sha, foreign)


def foreign_error(state: BranchState, where: str) -> GitError:
    shown = ", ".join(state.foreign[:5]) + (" …" if len(state.foreign) > 5 else "")
    return GitError(
        f"{where} branch '{state.name}' holds commits VulnPilot didn't make ({shown}); "
        "nothing was pushed. Move that work to another branch, or delete the branch "
        "to let VulnPilot rebuild it."
    )


def commit(worktree: Path, paths: list[str], message: str) -> str:
    """Commit exactly ``paths`` in the worktree (detached at the base commit); return the SHA."""
    _must(git(["add", "--", *paths], worktree), "git add")
    staged = _must(git(["diff", "--cached", "--name-only"], worktree), "git diff")
    extra = set(staged.splitlines()) - set(paths)
    if extra:
        raise GitError(f"refusing to commit unexpected files: {sorted(extra)}")
    result = git(["commit", "--quiet", "--no-verify", "-m", message], worktree)
    if not result.ok and "tell me who you are" in result.stderr.lower():
        raise GitError("git has no user.name / user.email set for this repo; set them first")
    _must(result, "git commit")
    return _must(git(["rev-parse", "HEAD"], worktree), "git rev-parse")


def same_change(repo: Path, a: str, b: str) -> bool:
    """Same parent and same tree: pushing ``b`` over ``a`` would change nothing."""
    out = _must(
        git(["rev-parse", f"{a}^{{tree}}", f"{b}^{{tree}}", f"{a}^", f"{b}^"], repo),
        "git rev-parse",
    ).split()
    return out[0] == out[1] and out[2] == out[3]


def push(repo: Path, sha: str, branch: str, expected: str | None, env: dict[str, str]) -> None:
    """Force-push ``sha`` to ``branch``, but only if origin still has ``expected`` there."""
    lease = f"--force-with-lease=refs/heads/{branch}:{expected or ''}"
    result = git(["push", "--quiet", lease, "origin", f"{sha}:refs/heads/{branch}"], repo, env=env)
    if not result.ok and "stale info" in result.stderr:
        raise GitError(f"'{branch}' changed on origin during the run; nothing was pushed. Re-run.")
    _must(result, f"git push to {branch}")


def set_local_branch(repo: Path, branch: str, sha: str) -> None:
    result = git(["branch", "--force", branch, sha], repo)
    if not result.ok and "used by worktree" in result.stderr:
        raise GitError(
            f"'{branch}' is checked out; switch to another branch so VulnPilot can rebuild it"
        )
    _must(result, f"could not update local branch {branch}")
