"""Live tests: the real osv-scanner against the fixtures (needs the tool and network).

Run with:  make integration
"""

import shutil
from datetime import date
from pathlib import Path

import pytest

from tests.conftest import ALL_FIXTURES, fixture_spec
from vulnpilot.config import Config
from vulnpilot.scanner import run_scan

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner not installed"),
]


@pytest.mark.parametrize("d", ALL_FIXTURES, ids=lambda d: d.name)
def test_live_scan_finds_expected(d: Path) -> None:
    result = run_scan(d, Config(severity_threshold="LOW"), today=date.today())
    for exp in fixture_spec(d)["expected"]["scan"]:
        assert any(
            f.package == exp["package"] and exp["advisory"] in f.aliases for f in result.findings
        ), exp
