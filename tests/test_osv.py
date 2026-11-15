from pathlib import Path

import pytest

from tests.conftest import UV_FIXTURES, fake_osv_runner, fixture_spec, osv_data
from vulnpilot.detect import detect_project
from vulnpilot.models import Severity
from vulnpilot.proc import ProcResult
from vulnpilot.sources.base import SourceError
from vulnpilot.sources.osv import OsvSource, parse_osv_json, preferred_id


@pytest.mark.parametrize("d", UV_FIXTURES, ids=lambda d: d.name)
def test_expected_findings_are_parsed(d: Path) -> None:
    findings = parse_osv_json(osv_data(d.name), "2.7.1")
    for exp in fixture_spec(d)["expected"]["scan"]:
        match = [
            f
            for f in findings
            if f.package == exp["package"]
            and f.installed_version == exp["installed"]
            and exp["advisory"] in f.aliases
        ]
        assert len(match) == 1, f"{exp} not found exactly once"


def test_alias_group_and_preferred_id() -> None:
    findings = parse_osv_json(osv_data("direct-pinned"))
    f = next(f for f in findings if "CVE-2024-35195" in f.aliases)
    assert f.advisory_id == "CVE-2024-35195"
    assert any(a.startswith("GHSA-") for a in f.aliases)
    assert f.key == "PyPI|requests|" + min(f.aliases)
    assert f.sources[0].tool == "osv-scanner"


def test_fixed_versions_are_above_installed_and_sorted() -> None:
    for f in parse_osv_json(osv_data("transitive")):
        assert f.fixed_versions, f.advisory_id
        assert f.fixed_versions == sorted(
            f.fixed_versions, key=lambda v: tuple(map(int, v.split(".")))
        )
        assert f.sources[0].fixed_version == f.fixed_versions[0]


def test_cve_2024_35195_fix_and_severity() -> None:
    f = next(f for f in parse_osv_json(osv_data("direct-pinned")) if "CVE-2024-35195" in f.aliases)
    assert f.fixed_versions[0] == "2.32.0"
    assert f.severity in {Severity.MEDIUM, Severity.HIGH}
    assert f.cvss is not None


def test_ghsa_label_used_when_no_cvss() -> None:
    data = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "Demo", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-aaaa-bbbb-cccc",
                                "aliases": [],
                                "database_specific": {"severity": "MODERATE"},
                                "affected": [],
                            }
                        ],
                        "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "max_severity": ""}],
                    }
                ]
            }
        ]
    }
    [f] = parse_osv_json(data)
    assert f.package == "demo"
    assert f.severity is Severity.MEDIUM
    assert f.cvss is None
    assert f.fixed_versions == []


def test_empty_results() -> None:
    assert parse_osv_json({"results": []}) == []


def test_preferred_id_order() -> None:
    assert preferred_id(["PYSEC-1", "GHSA-x", "CVE-2"]) == "CVE-2"
    assert preferred_id(["PYSEC-1", "GHSA-x"]) == "GHSA-x"
    assert preferred_id(["OSV-9"]) == "OSV-9"


def test_source_saves_raw_output(tmp_path: Path) -> None:
    project = detect_project(UV_FIXTURES[0])
    source = OsvSource(tmp_path / "raw", run=fake_osv_runner(project.root.name))
    findings = source.collect(project)
    assert findings
    assert findings[0].sources[0].tool_version == "2.7.1"
    assert (tmp_path / "raw" / "osv-scanner.json").is_file()


def test_scanner_error_is_reported(tmp_path: Path) -> None:
    project = detect_project(UV_FIXTURES[0])
    source = OsvSource(tmp_path, run=lambda cmd: ProcResult(127, "", "boom\nreal reason"))
    with pytest.raises(SourceError, match=r"exit 127.*real reason"):
        source.collect(project)
