"""One "how to fix it" line for each error that stops a run (exit code 2).

Kept in one table so every message gets a hint, and the hints stay consistent.
"""

from __future__ import annotations

from vulnpilot.config import ConfigError
from vulnpilot.detect import DetectError
from vulnpilot.fixers.base import LockError
from vulnpilot.git_ops import GitError
from vulnpilot.github import GitHubError
from vulnpilot.runner import FixError
from vulnpilot.sources.base import SourceError
from vulnpilot.sources.imports import ImportFileError
from vulnpilot.worktree import WorktreeError

_CREDENTIALS = (
    "a private package index needs credentials: set them in your environment the way "
    "`uv sync` / `poetry install` expects (e.g. UV_INDEX_<NAME>_USERNAME / _PASSWORD, "
    "or POETRY_HTTP_BASIC_<NAME>_USERNAME / _PASSWORD)"
)

# (error type, text in the message or "" for any, hint). First match wins.
_HINTS: list[tuple[type[Exception], str, str]] = [
    (ConfigError, "", "fix vulnpilot.yml; the README lists every key and its default"),
    (
        DetectError,
        "no pyproject.toml",
        "run it on the project folder: `vulnpilot scan path/to/project`",
    ),
    (
        DetectError,
        "no uv.lock or poetry.lock",
        "create and commit a lockfile first: `uv lock` or `poetry lock`",
    ),
    (
        DetectError,
        "workspace",
        "uv workspaces are not supported in v1; run it on a single-project repo",
    ),
    (DetectError, "not valid TOML", "fix the TOML syntax in pyproject.toml"),
    (
        ImportFileError,
        "",
        "pass a Trivy (`--format json`) or Wiz (`--json-output-file`) JSON report",
    ),
    (
        SourceError,
        "not installed",
        "install OSV-Scanner v2 (`brew install osv-scanner`), then run `vulnpilot doctor`",
    ),
    (SourceError, "timed out", "check your network connection and run it again"),
    (SourceError, "", "run `osv-scanner scan source -L <lockfile>` to see the full error"),
    (
        WorktreeError,
        "not inside a git repository",
        "`fix` needs a git repo with the project committed; `scan` works without git",
    ),
    (
        WorktreeError,
        "could not fetch",
        "check you can `git fetch origin`, or set pr.base_branch in vulnpilot.yml "
        "to your default branch",
    ),
    (
        WorktreeError,
        "no local branch",
        "set pr.base_branch in vulnpilot.yml to your default branch (e.g. master)",
    ),
    (
        WorktreeError,
        "has no pyproject.toml on",
        "commit pyproject.toml and the lockfile to the base branch first",
    ),
    (WorktreeError, "", "run `git worktree prune` and try again"),
    (FixError, "installing the project failed", f"see the log; if it is a 401/403, {_CREDENTIALS}"),
    (
        FixError,
        "tests already fail",
        "fix the tests on the base branch, or set validate.test in vulnpilot.yml "
        "(`none` skips tests)",
    ),
    (
        FixError,
        "files other than",
        "an install or test step wrote files into the repo; add them to .gitignore",
    ),
    (LockError, "401", _CREDENTIALS),
    (LockError, "403", _CREDENTIALS),
    (
        LockError,
        "poetry is not installed",
        "install Poetry (https://python-poetry.org/docs/#installation)",
    ),
    (LockError, "", "the full resolver message is in logs/resolver.log in the run folder"),
    (
        GitError,
        "user.name",
        '`git config user.name "Your Name"` and `git config user.email you@example.com`',
    ),
    (GitError, "owner/repo", "set pr.repo: owner/name in vulnpilot.yml"),
    (
        GitError,
        "no 'origin' remote",
        "add the GitHub remote (`git remote add origin …`), or use --no-push",
    ),
    (GitError, "changed on origin", "someone pushed to the branch during the run; run it again"),
    (
        GitError,
        "holds commits",
        "move that work to another branch, or delete the branch so VulnPilot can rebuild it",
    ),
    (
        GitError,
        "git push",
        "check you can push (`git push --dry-run origin HEAD`) and which account pr.gh_user names",
    ),
    (
        GitHubError,
        "was pushed, but",
        "open the PR by hand: `gh pr create --head vulnpilot/security-fixes`, or run it again",
    ),
    (GitHubError, "no login", "`gh auth login`, then `gh auth switch` back to your usual account"),
    (
        GitHubError,
        "cannot push to",
        "set pr.gh_user in vulnpilot.yml to an account with write access",
    ),
    (
        GitHubError,
        "",
        "check `gh auth status` and that this account can see the repo (`gh repo view owner/name`)",
    ),
]


def hint_for(exc: Exception) -> str | None:
    text = str(exc)
    for kind, needle, hint in _HINTS:
        if isinstance(exc, kind) and needle in text:
            return hint
    return None
