import subprocess
from datetime import UTC, datetime
from pathlib import Path

from vulnpilot.worktree import prune_stale


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout  # fmt: skip


def test_only_old_vulnpilot_worktrees_are_removed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "f").write_text("x")
    git(repo, "add", "f")
    git(repo, "commit", "-q", "-m", "c")
    runs = tmp_path / "cache" / "runs"
    old = runs / "20261116T080000Z-aaaaaa" / "worktree"
    recent = runs / "20261116T115500Z-bbbbbb" / "worktree"
    mine = tmp_path / "someone-elses-worktree"
    for path in (old, recent, mine):
        git(repo, "worktree", "add", "--detach", "-q", str(path), "HEAD")

    removed = prune_stale(repo, runs, now=datetime(2026, 11, 16, 15, 0, tzinfo=UTC))

    assert [p.name for p in removed] == ["worktree"] and removed[0].parent.name.startswith(
        "20261116T08"
    )
    listed = git(repo, "worktree", "list")
    assert str(recent.resolve()) in listed and str(mine.resolve()) in listed
    assert str(old.resolve()) not in listed and not old.exists()
