import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import FIXTURES, TESTS, fake_osv_runner
from vulnpilot.cli import app
from vulnpilot.config import Config
from vulnpilot.lockgraph import lock_versions
from vulnpilot.models import ExitCode
from vulnpilot.report.json_out import write_scan_json
from vulnpilot.scanner import run_scan
from vulnpilot.sources.imports import ImportFileError, detect_format, load_import

IMPORTS = TESTS / "data" / "imports"
PROJECT = FIXTURES / "uv" / "tests-break"
LOCK = lock_versions(PROJECT / "uv.lock")
SECRET = "FAKE-SECRET-VALUE-NOT-REAL-0123456789"  # noqa: S105 - test marker


@pytest.mark.parametrize(
    ("name", "tool", "kind"),
    [
        ("trivy-fs.json", "trivy", "repo"),
        ("trivy-image.json", "trivy", "image"),
        ("wiz-dir.json", "wiz", "repo"),
        ("wiz-image.json", "wiz", "image"),
    ],
)
def test_detect_format(name: str, tool: str, kind: str) -> None:
    data = json.loads((IMPORTS / name).read_text("utf-8"))
    assert detect_format(data) == (tool, kind)


@pytest.mark.parametrize("name", ["trivy-image.json", "wiz-image.json"])
def test_image_findings_are_mapped_onto_the_lockfile(name: str) -> None:
    imp = load_import(IMPORTS / name, LOCK)
    assert imp.target == "image:vulnpilot-sample:local"
    pkgs = {f.package: f for f in imp.findings}
    # Same version in the image and the lockfile: a normal, fixable finding.
    assert pkgs["requests"].in_lockfile and not pkgs["requests"].fixed_in_source
    # The image has urllib3 2.2.1; the lockfile already has 2.8.0.
    urllib3 = [f for f in imp.findings if f.package == "urllib3"]
    assert urllib3 and all(f.fixed_in_source and f.installed_version == "2.8.0" for f in urllib3)
    assert {h.installed_version for f in urllib3 for h in f.sources} == {"2.2.1"}
    # pip comes with the base image, not the lockfile.
    assert not pkgs["pip"].in_lockfile
    assert any(f.ecosystem == "os" and not f.in_lockfile for f in imp.findings)


def test_repo_scan_targets_source() -> None:
    imp = load_import(IMPORTS / "trivy-fs.json", LOCK)
    assert imp.target == "source" and imp.findings
    assert all(f.in_lockfile and not f.fixed_in_source for f in imp.findings)


def test_one_cve_from_three_sources_is_one_finding() -> None:
    result = run_scan(
        PROJECT,
        Config(severity_threshold="LOW"),
        run=fake_osv_runner("tests-break"),
        today=date(2026, 11, 15),
        imports=[IMPORTS / "trivy-image.json", IMPORTS / "wiz-image.json"],
    )
    hits = [f for f in result.findings if "CVE-2024-35195" in f.aliases]
    assert len(hits) == 1
    assert {h.tool for h in hits[0].sources} == {"osv-scanner", "trivy", "wiz"}
    assert hits[0].aliases[0].startswith(("CVE", "GHSA", "PYSEC"))
    assert "wiz" in result.tool_versions  # Trivy 0.67 does not record its own version


def _with_secrets(tmp_path: Path) -> list[Path]:
    trivy = json.loads((IMPORTS / "trivy-fs.json").read_text("utf-8"))
    trivy["Results"].append(
        {
            "Target": "app/settings.py",
            "Class": "secret",
            "Secrets": [{"RuleID": "stripe", "Match": f"KEY={SECRET}", "Severity": "CRITICAL"}],
        }
    )
    wiz = json.loads((IMPORTS / "wiz-dir.json").read_text("utf-8"))
    wiz["result"]["secrets"] = [{"path": "app/settings.py", "snippet": SECRET}]
    paths = [tmp_path / "trivy.json", tmp_path / "wiz.json"]
    paths[0].write_text(json.dumps(trivy), "utf-8")
    paths[1].write_text(json.dumps(wiz), "utf-8")
    return paths


def test_secret_findings_are_never_parsed_or_stored(tmp_path: Path) -> None:
    paths = _with_secrets(tmp_path)
    result = run_scan(
        PROJECT,
        Config(severity_threshold="LOW"),
        run=fake_osv_runner("tests-break"),
        imports=paths,
    )
    out = tmp_path / "report.json"
    write_scan_json(result, out)
    assert SECRET not in out.read_text("utf-8")
    assert SECRET not in repr(result.findings)
    stored = [p for p in result.raw_dir.rglob("*") if p.is_file()]
    assert all(SECRET not in p.read_text("utf-8", errors="ignore") for p in stored)


def test_compromised_trivy_release_warns(tmp_path: Path) -> None:
    data = json.loads((IMPORTS / "trivy-fs.json").read_text("utf-8"))
    data["Trivy"] = {"Version": "0.69.5"}
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(data), "utf-8")
    [warning] = load_import(path, LOCK).warnings
    assert "compromised release" in warning
    data["Trivy"] = {"Version": "0.69.3"}
    path.write_text(json.dumps(data), "utf-8")
    assert load_import(path, LOCK).warnings == []


@pytest.mark.parametrize(
    ("content", "match"),
    [("{not json", "not valid JSON"), ('{"hello": 1}', "not a Trivy or Wiz JSON report")],
)
def test_bad_import_file(tmp_path: Path, content: str, match: str) -> None:
    path = tmp_path / "scan.json"
    path.write_text(content, "utf-8")
    with pytest.raises(ImportFileError, match=match):
        load_import(path, LOCK)
    result = CliRunner().invoke(app, ["scan", str(PROJECT), "--import", str(path)])
    assert result.exit_code == ExitCode.ERROR
    assert "scan.json" in result.output


def test_committed_samples_hold_no_tenant_data() -> None:
    for path in IMPORTS.glob("*.json"):
        text = path.read_text("utf-8")
        for needle in (
            "app.wiz.io",
            "serviceAccount",
            "/Users/",
            "/home/",
            'failedPolicyMatches": [{"policy": {"id',
        ):
            assert needle not in text, (path.name, needle)
