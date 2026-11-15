"""Stage 4 done-when, offline from GitHub: a local bare repo stands in for origin and a fake
host stands in for GitHub. Running `fix` twice gives one PR, updated, not two; --no-push
pushes nothing; a branch with someone else's commits is never overwritten.

Runs real uv, osv-scanner, PyPI and pytest. Run with:  make integration
"""

import importlib.util
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest

from vulnpilot.config import Config
from vulnpilot.git_ops import TRAILER, GitError
from vulnpilot.github import PullRequest
from vulnpilot.pr_body import MARKER
from vulnpilot.runner import run_fix

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner not installed"),
]
BRANCH = "vulnpilot/security-fixes"


def _fixture_repo_module() -> ModuleType:
    path = Path(__file__).parent.parent / "scripts" / "fixture_repo.py"
    spec = importlib.util.spec_from_file_location("fixture_repo", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


@dataclass
class FakeHost:
    prs: dict[int, dict[str, object]] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)

    def push_env(self) -> dict[str, str]:
        return {}

    def find_open(self, branch: str) -> PullRequest | None:
        open_ = [n for n, p in self.prs.items() if p["open"] and p["head"] == branch]
        return (
            PullRequest(max(open_), f"https://example.invalid/pull/{max(open_)}") if open_ else None
        )

    def create(self, base: str, branch: str, title: str, body_file: Path) -> PullRequest:
        n = len(self.prs) + 1
        self.prs[n] = {"head": branch, "base": base, "title": title, "open": True}
        self.prs[n]["body"] = body_file.read_text("utf-8")
        self.events.append(f"create #{n}")
        return PullRequest(n, f"https://example.invalid/pull/{n}")

    def update(self, pr: PullRequest, title: str, body_file: Path) -> None:
        self.prs[pr.number].update(title=title, body=body_file.read_text("utf-8"))
        self.events.append(f"update #{pr.number}")

    def decorate(self, pr: PullRequest, labels: list[str], reviewers: list[str]) -> list[str]:
        return []


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    mod = _fixture_repo_module()
    r: Path = mod.make_fixture_repo("direct-in-range", tmp_path / "repo")
    mod.add_bare_origin(r, tmp_path / "origin.git")
    return r


def remote_sha(repo: Path) -> str:
    out = git(repo, "ls-remote", "origin", f"refs/heads/{BRANCH}")
    return out.split()[0] if out else ""


def test_two_runs_give_one_pr_and_a_moved_base_rebuilds_it(repo: Path) -> None:
    host = FakeHost()
    first = run_fix(repo, Config(severity_threshold="LOW"), host=host)
    assert first.pr_action == "created" and first.pr and first.pr.number == 1
    sha1 = remote_sha(repo)
    assert sha1 == first.commit_sha
    assert git(repo, "diff", "--name-only", f"origin/main..{sha1}").splitlines() == ["uv.lock"]
    assert f"{TRAILER}: {first.report.run_id}" in git(repo, "log", "-1", "--format=%B", sha1)  # type: ignore[union-attr]
    body = str(host.prs[1]["body"])
    assert body.startswith(MARKER) and "## Fixed" in body

    second = run_fix(repo, Config(severity_threshold="LOW"), host=host)
    assert second.pr_action == "unchanged" and remote_sha(repo) == sha1
    assert host.events == ["create #1", "update #1"]

    (repo / "NOTES.md").write_text("base moved\n")
    git(repo, "add", "NOTES.md")
    git(repo, "commit", "-q", "-m", "base moves on")
    git(repo, "push", "-q", "origin", "main")
    third = run_fix(repo, Config(severity_threshold="LOW"), host=host)
    assert third.pr_action == "updated" and remote_sha(repo) != sha1
    assert git(repo, "rev-parse", f"{remote_sha(repo)}^") == git(repo, "rev-parse", "origin/main")
    assert host.events == ["create #1", "update #1", "update #1"] and len(host.prs) == 1

    host.prs[1]["open"] = False  # merged or closed: the next run opens a new PR
    fourth = run_fix(repo, Config(severity_threshold="LOW"), host=host)
    assert fourth.pr_action == "created" and fourth.pr and fourth.pr.number == 2


def test_no_push_commits_locally_and_pushes_nothing(repo: Path) -> None:
    outcome = run_fix(repo, Config(severity_threshold="LOW"), push_pr=False)
    assert outcome.pr_action == "local" and outcome.body_path and outcome.body_path.is_file()
    assert git(repo, "rev-parse", BRANCH) == outcome.commit_sha
    assert remote_sha(repo) == ""
    assert git(repo, "branch", "--show-current") == "main"  # the checkout is untouched
    assert git(repo, "status", "--porcelain") == ""


def test_branch_with_human_commits_is_never_overwritten(repo: Path) -> None:
    git(repo, "switch", "-q", "-c", BRANCH)
    (repo / "mine.txt").write_text("human work\n")
    git(repo, "add", "mine.txt")
    git(repo, "commit", "-q", "-m", "my own change")
    git(repo, "push", "-q", "origin", BRANCH)
    git(repo, "switch", "-q", "main")
    before = remote_sha(repo)
    host = FakeHost()
    with pytest.raises(GitError, match="holds commits VulnPilot didn't make"):
        run_fix(repo, Config(severity_threshold="LOW"), host=host)
    assert remote_sha(repo) == before and host.events == []
