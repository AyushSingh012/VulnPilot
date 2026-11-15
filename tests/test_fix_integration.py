"""Stage 3 done-when: `fix` on every fixture lands in the states its fixture.yaml expects.

Runs real uv, osv-scanner, PyPI and pytest. Run with:  make integration
"""

import importlib.util
import shutil
from pathlib import Path
from types import ModuleType

import pytest
from packaging.version import Version

from tests.conftest import UV_FIXTURES, fixture_spec
from vulnpilot.config import Config
from vulnpilot.models import ExitCode
from vulnpilot.runner import FixError, run_fix

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner not installed"),
]


def _fixture_repo_module() -> ModuleType:
    path = Path(__file__).parent.parent / "scripts" / "fixture_repo.py"
    spec = importlib.util.spec_from_file_location("fixture_repo", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("d", UV_FIXTURES, ids=lambda d: d.name)
def test_fix_matches_expected(d: Path, tmp_path: Path) -> None:
    repo = _fixture_repo_module().make_fixture_repo(d.name, tmp_path / d.name)
    expected = fixture_spec(d)["expected"]["fix"]

    if expected["exit_code"] == ExitCode.ERROR:
        with pytest.raises(FixError, match=expected["error_contains"]):
            run_fix(repo, Config())
        return

    outcome = run_fix(repo, Config())
    assert outcome.report is not None
    assert outcome.exit_code == expected["exit_code"]
    assert sorted(outcome.changed) == sorted(expected["changed_files"])

    findings = {f.key: f for f in outcome.report.findings_before}
    for exp in expected["results"]:
        mine = [
            r for r in outcome.report.results if findings[r.finding_key].package == exp["package"]
        ]
        assert mine, exp
        statuses = {r.status.value for r in mine}
        assert exp["status"] in statuses, (exp, statuses)
        hit = next(r for r in mine if r.status.value == exp["status"])
        if exp.get("method"):
            assert hit.upgrade is not None and hit.upgrade.method == exp["method"]
        if exp.get("min_to_version"):
            assert hit.upgrade is not None
            assert Version(hit.upgrade.to_version) >= Version(exp["min_to_version"])
        if exp.get("note_contains"):
            assert exp["note_contains"] in hit.note
