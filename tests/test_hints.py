import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import fixture_dir
from vulnpilot.cli import app
from vulnpilot.config import ConfigError
from vulnpilot.detect import DetectError
from vulnpilot.fixers.base import LockError
from vulnpilot.git_ops import GitError
from vulnpilot.github import GitHubError
from vulnpilot.hints import hint_for
from vulnpilot.models import ExitCode
from vulnpilot.runner import FixError
from vulnpilot.sources.base import SourceError
from vulnpilot.sources.imports import ImportFileError
from vulnpilot.worktree import WorktreeError


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (ConfigError("x"), "README"),
        (DetectError("no uv.lock or poetry.lock in /p"), "uv lock"),
        (SourceError("osv-scanner is not installed"), "brew install osv-scanner"),
        (ImportFileError("x"), "JSON report"),
        (WorktreeError("/p is not inside a git repository"), "`scan` works without git"),
        (FixError("installing the project failed on origin/main"), "UV_INDEX_"),
        (FixError("tests already fail on origin/main"), "validate.test"),
        (LockError("HTTP 401 Unauthorized"), "credentials"),
        (LockError("No solution found"), "resolver.log"),
        (GitError("git has no user.name / user.email set"), "git config user.name"),
        (GitError("origin branch 'x' holds commits VulnPilot didn't make"), "delete the branch"),
        (GitHubError("'x' was pushed, but could not open"), "gh pr create"),
        (GitHubError("someone cannot push to o/r"), "pr.gh_user"),
    ],
)
def test_every_stop_has_a_fix_hint(exc: Exception, expected: str) -> None:
    hint = hint_for(exc)
    assert hint is not None and expected in hint


def test_cli_prints_the_hint(tmp_path: Path) -> None:
    # A project outside any git repo: `fix` stops before doing anything, with a hint.
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy(fixture_dir("transitive") / name, tmp_path / name)
    result = CliRunner().invoke(app, ["fix", str(tmp_path)])
    assert result.exit_code == ExitCode.ERROR
    assert "not inside a git repository" in result.output
    assert "Fix:" in result.output and "`scan` works without git" in result.output
