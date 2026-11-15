import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from vulnpilot import proc
from vulnpilot.github import GhCli, GitHubError, PullRequest
from vulnpilot.proc import ProcResult

FAKE_TOKEN = "fake-test-token"  # noqa: S105 - not a credential


class FakeGh:
    """Answers gh commands from a table of (argv prefix -> result); records every call."""

    def __init__(self, answers: dict[tuple[str, ...], ProcResult]) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []
        self.envs: list[Mapping[str, str]] = []

    def __call__(
        self,
        cmd: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ProcResult:
        args = list(cmd[1:])
        self.calls.append(args)
        self.envs.append(env or {})
        for prefix, result in self.answers.items():
            if tuple(args[: len(prefix)]) == prefix:
                return result
        return ProcResult(0, "", "")


@pytest.fixture
def gh(monkeypatch: pytest.MonkeyPatch) -> FakeGh:
    fake = FakeGh(
        {
            ("auth", "token"): ProcResult(0, FAKE_TOKEN + "\n", ""),
            ("repo", "view"): ProcResult(0, json.dumps({"viewerPermission": "ADMIN"}), ""),
            ("pr", "list"): ProcResult(
                0,
                json.dumps(
                    [
                        {
                            "number": 3,
                            "url": "https://github.com/o/r/pull/3",
                            "isCrossRepository": True,
                        },
                        {
                            "number": 7,
                            "url": "https://github.com/o/r/pull/7",
                            "isCrossRepository": False,
                        },
                    ]
                ),
                "",
            ),
            ("pr", "create"): ProcResult(0, "https://github.com/o/r/pull/9\n", ""),
            ("label", "list"): ProcResult(0, json.dumps([{"name": "Security"}]), ""),
        }
    )
    monkeypatch.setattr(proc, "run", fake)
    return fake


def test_named_account_token_is_used_only_in_env(gh: FakeGh) -> None:
    cli = GhCli("o/r", user="someone")
    cli.check_access()
    assert gh.calls[0] == ["auth", "token", "--user", "someone"]
    assert gh.envs[1]["GH_TOKEN"] == FAKE_TOKEN
    assert cli.push_env() == {"GH_TOKEN": FAKE_TOKEN}
    assert not any(FAKE_TOKEN in a for call in gh.calls for a in call)


def test_active_account_by_default(gh: FakeGh) -> None:
    cli = GhCli("o/r")
    assert cli.push_env() == {}
    assert cli.find_open("vulnpilot/security-fixes") == PullRequest(
        7, "https://github.com/o/r/pull/7"
    )


def test_create_and_decorate(gh: FakeGh, tmp_path: Path) -> None:
    cli = GhCli("o/r")
    pr = cli.create("main", "vulnpilot/security-fixes", "t", tmp_path / "b.md")
    assert pr.number == 9
    warnings = cli.decorate(pr, ["security", "dependencies"], [])
    assert warnings == ["labels not in the repo, not added: dependencies"]
    assert ["pr", "edit", "9", "--repo", "o/r", "--add-label", "security"] in gh.calls


def test_read_only_access_is_refused(gh: FakeGh) -> None:
    gh.answers[("repo", "view")] = ProcResult(0, json.dumps({"viewerPermission": "READ"}), "")
    with pytest.raises(GitHubError, match="cannot push to o/r"):
        GhCli("o/r").check_access()


def test_missing_login_is_explained(gh: FakeGh) -> None:
    gh.answers[("auth", "token")] = ProcResult(1, "", "no oauth token found for nobody\n")
    with pytest.raises(GitHubError, match=r"gh has no login for nobody.*gh auth login"):
        GhCli("o/r", user="nobody")
