"""Copy a fixture into its own throwaway git repo (branch main, no remote).

Usage:  uv run python scripts/fixture_repo.py <fixture-name> <dest-dir>

`vulnpilot fix <dest-dir>` then works on it like a real project at a repo root. Used by
the integration tests and handy for trying `fix` by hand.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
_IGNORE = shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", "fixture.yaml")


def make_fixture_repo(name: str, dest: Path) -> Path:
    matches = list(FIXTURES.glob(f"*/{name}/fixture.yaml"))
    if not matches:
        raise SystemExit(f"no fixture named {name}")
    shutil.copytree(matches[0].parent, dest, ignore=_IGNORE)
    (dest / ".gitignore").write_text(".venv/\n__pycache__/\n.pytest_cache/\n", "utf-8")

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *args],
            cwd=dest,
            check=True,
            capture_output=True,
        )

    git("init", "-q", "-b", "main")
    # VulnPilot commits in this repo too; give it a local identity of its own.
    git("config", "user.name", "fixture")
    git("config", "user.email", "fixture@example.invalid")
    git("add", "-A")
    git("commit", "-q", "-m", f"fixture {name}")
    return dest


def add_bare_origin(repo: Path, origin: Path) -> Path:
    """Give ``repo`` a local bare ``origin`` with ``main`` pushed, like a GitHub remote."""
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    for args in (["remote", "add", "origin", str(origin)], ["push", "-q", "origin", "main"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    return origin


if __name__ == "__main__":
    make_fixture_repo(sys.argv[1], Path(sys.argv[2]))
