"""Stage 4 done-when, against real GitHub: `fix` twice on a throwaway repo gives one PR.

The sandbox repo's main branch is reset to a fixture on every run, so use a repo that
holds nothing else. Skipped unless these are set:

    VULNPILOT_SANDBOX         owner/name, e.g. someone/vulnpilot-sandbox
    VULNPILOT_SANDBOX_REMOTE  git URL to push to, e.g. git@github.com:someone/vulnpilot-sandbox.git
    VULNPILOT_GH_USER         gh account that can push there (optional; else the active one)

Run with:  make github-test
"""

import importlib.util
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from vulnpilot.config import Config, PRConfig
from vulnpilot.models import ExitCode
from vulnpilot.pr_body import MARKER
from vulnpilot.runner import run_fix

SANDBOX = os.environ.get("VULNPILOT_SANDBOX", "")
REMOTE = os.environ.get("VULNPILOT_SANDBOX_REMOTE", "")
GH_USER = os.environ.get("VULNPILOT_GH_USER") or None
BRANCH = "vulnpilot/security-fixes"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.github,
    pytest.mark.skipif(not (SANDBOX and REMOTE), reason="no sandbox repo configured"),
    pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner not installed"),
]


def _fixture_repo_module() -> ModuleType:
    path = Path(__file__).parent.parent / "scripts" / "fixture_repo.py"
    spec = importlib.util.spec_from_file_location("fixture_repo", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gh(*args: str) -> str:
    env = dict(os.environ)
    if GH_USER:
        token = subprocess.run(
            ["gh", "auth", "token", "--user", GH_USER], check=True, capture_output=True, text=True
        ).stdout.strip()
        env["GH_TOKEN"] = token
    return subprocess.run(
        ["gh", *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def open_prs() -> list[dict[str, object]]:
    out = gh("pr", "list", "--repo", SANDBOX, "--head", BRANCH, "--state", "open",
             "--json", "number,title,body")  # fmt: skip
    prs: list[dict[str, object]] = json.loads(out)
    return prs


def close_all() -> None:
    for pr in open_prs():
        gh("pr", "close", str(pr["number"]), "--repo", SANDBOX, "--delete-branch")
    subprocess.run(
        ["git", "push", "-q", REMOTE, f":refs/heads/{BRANCH}"], capture_output=True, check=False
    )


@pytest.fixture
def sandbox(tmp_path: Path) -> Iterator[Path]:
    repo: Path = _fixture_repo_module().make_fixture_repo("tests-break", tmp_path / "repo")
    subprocess.run(["git", "remote", "add", "origin", REMOTE], cwd=repo, check=True)
    subprocess.run(
        ["git", "push", "-q", "--force", "origin", "main"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    close_all()
    yield repo
    close_all()


def test_two_runs_give_one_pr_on_github(sandbox: Path) -> None:
    cfg = Config(pr=PRConfig(gh_user=GH_USER, repo=SANDBOX, labels=["security"]))
    first = run_fix(sandbox, cfg)
    assert first.exit_code == ExitCode.FINDINGS_REMAIN  # jinja2 breaks a test and stays out
    assert first.pr_action == "created" and first.pr is not None

    second = run_fix(sandbox, cfg)
    assert second.pr is not None and second.pr.number == first.pr.number
    assert second.pr_action in {"unchanged", "updated"}

    [pr] = open_prs()
    assert pr["number"] == first.pr.number
    body = str(pr["body"])
    assert body.startswith(MARKER)
    assert "## Fixed" in body and "### Needs code changes" in body
    [jinja_row] = [line for line in body.splitlines() if line.startswith("| `jinja2`")]
    assert "breaks tests: tests/test_smoke.py::test_jinja2_is_exactly_312" in jinja_row
    assert "/Users/" not in body and "/home/" not in body
