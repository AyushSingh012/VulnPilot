import subprocess
from pathlib import Path

import pytest

from vulnpilot.git_ops import (
    TRAILER,
    GitError,
    branch_state,
    commit,
    foreign_commits,
    push,
    repo_slug,
    same_change,
)


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:octo/demo.git",
        "git@github-personal:octo/demo.git",
        "ssh://git@github.com/octo/demo",
        "https://github.com/octo/demo.git",
        "https://user@github.com/octo/demo/",
    ],
)
def test_repo_slug(tmp_path: Path, url: str) -> None:
    run(tmp_path, "init", "-q")
    run(tmp_path, "remote", "add", "origin", url)
    assert repo_slug(tmp_path) == "octo/demo"


def test_repo_slug_rejects_non_github_url(tmp_path: Path) -> None:
    run(tmp_path, "init", "-q")
    run(tmp_path, "remote", "add", "origin", "/srv/git/demo")
    with pytest.raises(GitError, match="owner/repo"):
        repo_slug(tmp_path)


def run(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    run(r, "init", "-q", "-b", "main")
    run(r, "config", "user.name", "t")
    run(r, "config", "user.email", "t@example.invalid")
    (r / "uv.lock").write_text("v1\n")
    (r / "pyproject.toml").write_text("[project]\n")
    run(r, "add", "-A")
    run(r, "commit", "-q", "-m", "base")
    return r


def _vp_commit(repo: Path, text: str, run_id: str = "run-1") -> str:
    (repo / "uv.lock").write_text(text)
    return commit(repo, ["uv.lock"], f"fix\n\n{TRAILER}: {run_id}")


def test_vulnpilot_commits_are_not_foreign(repo: Path) -> None:
    base = run(repo, "rev-parse", "HEAD")
    run(repo, "switch", "-q", "-c", "vulnpilot/security-fixes")
    _vp_commit(repo, "v2\n")
    assert foreign_commits(repo, base, "HEAD") == []
    state = branch_state(repo, "vulnpilot/security-fixes", base, remote=False)
    assert state.sha and state.foreign == []


def test_human_commit_is_foreign_but_merges_are_not(repo: Path) -> None:
    run(repo, "switch", "-q", "-c", "vulnpilot/security-fixes")
    _vp_commit(repo, "v2\n")
    run(repo, "switch", "-q", "main")
    (repo / "README").write_text("x")
    run(repo, "add", "README")
    run(repo, "commit", "-q", "-m", "main moves on")
    run(repo, "switch", "-q", "vulnpilot/security-fixes")
    run(repo, "merge", "-q", "--no-edit", "main")  # GitHub's "Update branch"
    assert foreign_commits(repo, "main", "HEAD") == []
    (repo / "notes.txt").write_text("human")
    run(repo, "add", "notes.txt")
    run(repo, "commit", "-q", "-m", "human work")
    assert len(foreign_commits(repo, "main", "HEAD")) == 1


def test_commit_refuses_extra_staged_files(repo: Path) -> None:
    (repo / "uv.lock").write_text("v2\n")
    (repo / "other.txt").write_text("x")
    run(repo, "add", "other.txt")
    with pytest.raises(GitError, match="unexpected files"):
        commit(repo, ["uv.lock"], "fix")


def test_same_change(repo: Path) -> None:
    base = run(repo, "rev-parse", "HEAD")
    a = _vp_commit(repo, "v2\n")
    run(repo, "checkout", "-q", "--detach", base)
    b = _vp_commit(repo, "v2\n", "run-2")
    run(repo, "checkout", "-q", "--detach", base)
    c = _vp_commit(repo, "v3\n", "run-3")
    assert a != b and same_change(repo, a, b)
    assert not same_change(repo, a, c)


def test_push_lease_refuses_when_origin_moved(repo: Path, tmp_path: Path) -> None:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    run(repo, "remote", "add", "origin", str(origin))
    base = run(repo, "rev-parse", "HEAD")
    first = _vp_commit(repo, "v2\n", "run-1")
    push(repo, first, "vulnpilot/security-fixes", None, {})
    run(repo, "checkout", "-q", "--detach", base)
    second = _vp_commit(repo, "v3\n", "run-2")
    with pytest.raises(GitError, match="changed on origin"):
        push(repo, second, "vulnpilot/security-fixes", None, {})  # we thought it did not exist
    push(repo, second, "vulnpilot/security-fixes", first, {})
    assert run(repo, "ls-remote", "origin", "refs/heads/vulnpilot/security-fixes").startswith(
        second
    )
