import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from vulnpilot.proc import ProcResult, Runner

TESTS = Path(__file__).parent
FIXTURES = TESTS / "fixtures"
OSV_DATA = TESTS / "data" / "osv"
UV_FIXTURES = sorted(p.parent for p in FIXTURES.glob("uv/*/fixture.yaml"))
POETRY_FIXTURES = sorted(p.parent for p in FIXTURES.glob("poetry/*/fixture.yaml"))
ALL_FIXTURES = UV_FIXTURES + POETRY_FIXTURES


def fixture_dir(name: str) -> Path:
    [match] = [d for d in ALL_FIXTURES if d.name == name]
    return match


def fixture_spec(d: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load((d / "fixture.yaml").read_text("utf-8"))
    return data


def osv_data(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((OSV_DATA / f"{name}.json").read_text("utf-8"))
    return data


def fake_osv_runner(name: str, *, version: str = "2.7.1") -> Runner:
    """Answers osv-scanner calls from saved output; no network, no scanner needed."""
    payload = (OSV_DATA / f"{name}.json").read_text("utf-8")

    def run(cmd: Sequence[str]) -> ProcResult:
        if list(cmd[1:]) == ["--version"]:
            return ProcResult(0, f"osv-scanner version: {version}\n", "")
        has_vulns = bool(json.loads(payload).get("results"))
        return ProcResult(1 if has_vulns else 0, payload, "")

    return run


@pytest.fixture(scope="session")
def shared_osv_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One local OSV database for the whole test run (36 MB; downloaded once)."""
    return tmp_path_factory.mktemp("osv-db")


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shared_osv_db: Path) -> Path:
    """Keep raw scanner output out of the real ~/.cache during tests."""
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.setenv("VULNPILOT_OFFLINE", "1")  # no KEV / EPSS lookups unless a test asks
    monkeypatch.setenv("VULNPILOT_OSV_DB", str(shared_osv_db))
    return cache
