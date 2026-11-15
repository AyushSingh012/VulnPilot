from datetime import UTC, datetime
from pathlib import Path

from vulnpilot.config import Config
from vulnpilot.git_ops import BranchState
from vulnpilot.github import PullRequest
from vulnpilot.models import ExitCode, FixResult, FixStatus, RunReport
from vulnpilot.runner import FixOutcome, _publish
from vulnpilot.worktree import Worktree


class NoCallsHost:
    def push_env(self) -> dict[str, str]:
        return {}

    def find_open(self, branch: str) -> PullRequest | None:
        return PullRequest(4, "https://example.invalid/pull/4")

    def create(self, base: str, branch: str, title: str, body_file: Path) -> PullRequest:
        raise AssertionError("no PR may be created")

    def update(self, pr: PullRequest, title: str, body_file: Path) -> None:
        raise AssertionError("no PR may be updated")

    def decorate(self, pr: PullRequest, labels: list[str], reviewers: list[str]) -> list[str]:
        raise AssertionError("no PR may be changed")


def _outcome(tmp_path: Path, statuses: list[FixStatus], changed: list[str]) -> FixOutcome:
    report = RunReport(
        run_id="r",
        repo="demo",
        commit_sha="0" * 40,
        started_at=datetime(2026, 11, 15, tzinfo=UTC),
        results=[FixResult(finding_key=f"k{i}", status=s) for i, s in enumerate(statuses)],
    )
    return FixOutcome(
        exit_code=ExitCode.FINDINGS_REMAIN, report=report, run_dir=tmp_path, changed=changed
    )


def _wt(tmp_path: Path) -> Worktree:
    # Never touched: _publish must return before any git step in these cases.
    missing = tmp_path / "no-such-repo"
    return Worktree(missing, missing, missing, "", "origin/main", "0" * 40)


STATE = BranchState("vulnpilot/security-fixes", None, [])


def test_introduced_blocks_the_pr(tmp_path: Path) -> None:
    out = _outcome(tmp_path, [FixStatus.FIXED_AND_VALIDATED, FixStatus.INTRODUCED], ["uv.lock"])
    _publish(out, _wt(tmp_path), Config(), STATE, NoCallsHost())
    assert out.pr_action == "none" and out.commit_sha is None
    assert "No PR" in out.pr_note and "INTRODUCED" in out.pr_note
    assert not (tmp_path / "pr-body.md").exists()


def test_nothing_fixed_leaves_an_open_pr_alone(tmp_path: Path) -> None:
    out = _outcome(tmp_path, [FixStatus.NO_SAFE_FIX], [])
    _publish(out, _wt(tmp_path), Config(), STATE, NoCallsHost())
    assert out.pr_action == "none" and "PR #4 was left as is" in out.pr_note
