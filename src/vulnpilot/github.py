"""Open or update the one VulnPilot PR through the ``gh`` CLI.

With ``pr.gh_user`` set, gh and git push run with that account's token (``GH_TOKEN``) for
VulnPilot's own commands only; the account active in gh is never switched. The token is
kept in memory and passed only to gh and git, never logged or written anywhere.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from vulnpilot import proc
from vulnpilot.proc import ProcResult, ToolNotFoundError, ToolTimeoutError

_PR_URL_RE = re.compile(r"https://\S+/pull/(\d+)")
_CAN_PUSH = {"ADMIN", "MAINTAIN", "WRITE"}


class GitHubError(Exception):
    """A gh step failed; the message says which and why."""


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str


class PRHost(Protocol):
    """Where the PR lives. The real one is :class:`GhCli`; tests use a fake."""

    def push_env(self) -> dict[str, str]:
        """Extra environment for ``git push`` (credentials for HTTPS remotes)."""
        ...

    def find_open(self, branch: str) -> PullRequest | None: ...

    def create(self, base: str, branch: str, title: str, body_file: Path) -> PullRequest: ...

    def update(self, pr: PullRequest, title: str, body_file: Path) -> None: ...

    def decorate(self, pr: PullRequest, labels: list[str], reviewers: list[str]) -> list[str]:
        """Add labels and reviewers; return warnings for the ones that could not be added."""
        ...


def _last_line(result: ProcResult) -> str:
    lines = [ln for ln in (result.stderr or result.stdout).strip().splitlines() if ln.strip()]
    return lines[-1] if lines else f"exit code {result.returncode}"


class GhCli:
    def __init__(self, slug: str, user: str | None = None) -> None:
        self.slug = slug
        self.user = user
        self._env = {**os.environ, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}
        if user:
            token = self._run(["auth", "token", "--user", user], f"gh has no login for {user}")
            self._env["GH_TOKEN"] = token.strip()

    def _run(self, args: list[str], what: str) -> str:
        try:
            result = proc.run(["gh", *args], timeout=120, env=self._env)
        except ToolNotFoundError as exc:
            raise GitHubError("gh is not installed") from exc
        except ToolTimeoutError as exc:
            raise GitHubError(f"gh {args[0]} timed out") from exc
        if not result.ok:
            hint = " (run: gh auth login)" if "auth" in args[:2] else ""
            raise GitHubError(f"{what}: {_last_line(result)}{hint}")
        return result.stdout

    def check_access(self) -> None:
        """Fail early, before any slow work, if this account cannot push to the repo."""
        out = self._run(
            ["repo", "view", self.slug, "--json", "viewerPermission"],
            f"cannot open {self.slug} on GitHub",
        )
        permission = json.loads(out).get("viewerPermission", "")
        if permission not in _CAN_PUSH:
            who = self.user or "the active gh account"
            raise GitHubError(
                f"{who} cannot push to {self.slug} (permission: {permission or 'none'}); "
                "set pr.gh_user in vulnpilot.yml to an account that can"
            )

    def push_env(self) -> dict[str, str]:
        return {"GH_TOKEN": self._env["GH_TOKEN"]} if "GH_TOKEN" in self._env else {}

    def find_open(self, branch: str) -> PullRequest | None:
        out = self._run(
            [
                "pr", "list", "--repo", self.slug, "--head", branch, "--state", "open",
                "--json", "number,url,isCrossRepository", "--limit", "20",
            ],
            "could not list pull requests",
        )  # fmt: skip
        mine = [p for p in json.loads(out) if not p.get("isCrossRepository")]
        if not mine:
            return None
        newest = max(mine, key=lambda p: p["number"])
        return PullRequest(int(newest["number"]), str(newest["url"]))

    def create(self, base: str, branch: str, title: str, body_file: Path) -> PullRequest:
        out = self._run(
            [
                "pr", "create", "--repo", self.slug, "--base", base, "--head", branch,
                "--title", title, "--body-file", str(body_file),
            ],
            "could not open the pull request",
        )  # fmt: skip
        match = _PR_URL_RE.search(out)
        if not match:
            raise GitHubError("gh pr create did not return a PR URL")
        return PullRequest(int(match.group(1)), match.group(0))

    def update(self, pr: PullRequest, title: str, body_file: Path) -> None:
        self._run(
            [
                "pr", "edit", str(pr.number), "--repo", self.slug,
                "--title", title, "--body-file", str(body_file),
            ],
            f"could not update PR #{pr.number}",
        )  # fmt: skip

    def decorate(self, pr: PullRequest, labels: list[str], reviewers: list[str]) -> list[str]:
        warnings: list[str] = []
        if labels:
            out = self._run(
                ["label", "list", "--repo", self.slug, "--json", "name", "--limit", "500"],
                "could not list labels",
            )
            existing = {str(lbl["name"]).lower() for lbl in json.loads(out)}
            usable = [lbl for lbl in labels if lbl.lower() in existing]
            missing = [lbl for lbl in labels if lbl.lower() not in existing]
            if missing:
                warnings.append(f"labels not in the repo, not added: {', '.join(missing)}")
            if usable:
                try:
                    self._run(
                        ["pr", "edit", str(pr.number), "--repo", self.slug,
                         "--add-label", ",".join(usable)],
                        "could not add labels",
                    )  # fmt: skip
                except GitHubError as exc:
                    warnings.append(str(exc))
        if reviewers:
            try:
                self._run(
                    ["pr", "edit", str(pr.number), "--repo", self.slug,
                     "--add-reviewer", ",".join(reviewers)],
                    "could not request reviewers",
                )  # fmt: skip
            except GitHubError as exc:
                warnings.append(str(exc))
        return warnings
