"""Every fixture is complete, its spec parses, and its lockfile holds the seeded versions."""

import tomllib
from pathlib import Path
from typing import Literal

import pytest
import yaml
from pydantic import BaseModel, ConfigDict

from vulnpilot.models import FixStatus, UpgradeMethod

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_DIRS = sorted(p.parent for p in FIXTURES.glob("*/*/fixture.yaml"))


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanExpect(_Strict):
    package: str
    installed: str
    advisory: str
    direct: bool | None = None
    path: list[str] | None = None


class ResultExpect(_Strict):
    package: str
    status: FixStatus
    method: UpgradeMethod | None = None
    min_to_version: str | None = None
    note_contains: str | None = None


class FixExpect(_Strict):
    exit_code: Literal[0, 1, 2]
    changed_files: list[str]
    results: list[ResultExpect]
    error_contains: str | None = None


class Expected(_Strict):
    scan: list[ScanExpect]
    fix: FixExpect


class FixtureSpec(_Strict):
    description: str
    manager: Literal["uv", "poetry"]
    seed: dict[str, str]
    expected: Expected


def load(d: Path) -> FixtureSpec:
    return FixtureSpec.model_validate(yaml.safe_load((d / "fixture.yaml").read_text("utf-8")))


def locked_versions(d: Path) -> dict[str, str]:
    lock = tomllib.loads((d / "uv.lock").read_text("utf-8"))
    return {p["name"]: p["version"] for p in lock["package"] if "version" in p}


def test_fixtures_exist() -> None:
    assert len(FIXTURE_DIRS) >= 7


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_fixture_is_complete(d: Path) -> None:
    spec = load(d)
    assert (d / "pyproject.toml").is_file()
    assert list((d / "tests").glob("test_*.py")), "fixture needs its own tests"
    if spec.manager == "uv":
        assert (d / "uv.lock").is_file(), "run scripts/regen_fixtures.py"


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_lockfile_holds_the_vulnerable_versions(d: Path) -> None:
    spec = load(d)
    locked = locked_versions(d)
    for pkg, version in spec.seed.items():
        assert locked.get(pkg) == version, f"{pkg} should be locked at {version}"
    for finding in spec.expected.scan:
        assert locked.get(finding.package) == finding.installed


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_expected_results_are_consistent(d: Path) -> None:
    fix = load(d).expected.fix
    fixed = [r for r in fix.results if r.status.counts_as_fixed]
    for r in fixed:
        assert r.method is not None and r.min_to_version is not None
    if fix.exit_code == 2:
        assert fix.changed_files == [] and fix.error_contains
    if not fixed:
        assert fix.changed_files == []
