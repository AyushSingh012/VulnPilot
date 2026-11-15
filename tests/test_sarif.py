import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft4Validator
from typer.testing import CliRunner

from tests.conftest import FIXTURES, TESTS, fake_osv_runner
from vulnpilot import scanner
from vulnpilot.cli import app
from vulnpilot.config import Config
from vulnpilot.models import FixResult, FixStatus, Severity
from vulnpilot.report.sarif import build_sarif, remaining
from vulnpilot.scanner import run_scan

SCHEMA = json.loads((TESTS / "data" / "sarif-schema-2.1.0.json").read_text("utf-8"))
PROJECT = FIXTURES / "uv" / "tests-break"
IMPORTS = TESTS / "data" / "imports"


def scan(**kw: Any) -> scanner.ScanResult:
    return run_scan(
        PROJECT,
        Config(severity_threshold="LOW"),
        run=fake_osv_runner("tests-break"),
        today=date(2026, 11, 15),
        **kw,
    )


def validate(payload: dict[str, Any]) -> None:
    errors = sorted(Draft4Validator(SCHEMA).iter_errors(payload), key=str)
    assert not errors, [e.message for e in errors[:5]]


def test_scan_sarif_passes_the_schema_and_points_at_the_lockfile() -> None:
    result = scan(imports=[IMPORTS / "trivy-image.json", IMPORTS / "wiz-image.json"])
    payload = build_sarif(result.shown, PROJECT / "uv.lock", "uv.lock")
    validate(payload)
    [run] = payload["runs"]
    by_rule = {r["ruleId"]: r for r in run["results"]}
    jinja = by_rule["CVE-2024-56326"]
    assert jinja["level"] == "error"
    region = jinja["locations"][0]["physicalLocation"]["region"]
    line = (PROJECT / "uv.lock").read_text("utf-8").splitlines()[region["startLine"] - 1]
    assert line == 'name = "jinja2"'
    assert jinja["partialFingerprints"]["vulnpilotFindingKey/v1"].startswith("PyPI|jinja2|")
    image_only = [r for r in run["results"] if "not in the lockfile" in r["message"]["text"]]
    assert image_only and all(
        "region" not in r["locations"][0]["physicalLocation"] for r in image_only
    )
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rules == {r["ruleId"] for r in run["results"]}
    assert all(
        float(r["properties"]["security-severity"]) > 0 for r in run["tool"]["driver"]["rules"]
    )


def test_fix_sarif_lists_only_what_is_still_open() -> None:
    result = scan()
    fixed, still = result.shown[0], result.shown[1]
    results = [
        FixResult(finding_key=fixed.key, status=FixStatus.FIXED_AND_VALIDATED),
        FixResult(finding_key=still.key, status=FixStatus.NO_SAFE_FIX, note="needs a major"),
    ]
    open_ = remaining(result.shown, results)
    assert open_ == [still]
    payload = build_sarif(
        open_, PROJECT / "uv.lock", "uv.lock", {r.finding_key: r for r in results}
    )
    validate(payload)
    [res] = payload["runs"][0]["results"]
    assert (
        res["properties"]["status"] == "NO_SAFE_FIX" and "needs a major" in res["message"]["text"]
    )


def test_unrated_findings_are_reported_as_errors() -> None:
    f = scan().shown[0].model_copy(update={"severity": Severity.UNKNOWN, "cvss": None})
    payload = build_sarif([f], PROJECT / "uv.lock", "uv.lock")
    validate(payload)
    assert payload["runs"][0]["results"][0]["level"] == "error"


def test_cli_scan_writes_sarif(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = scanner.run_scan

    def patched(path: Path, cfg: Config, only: Any = None, **kw: Any) -> scanner.ScanResult:
        return original(path, cfg, only, run=fake_osv_runner("tests-break"), **kw)

    monkeypatch.setattr("vulnpilot.cli.run_scan", patched)
    out = tmp_path / "scan.sarif"
    result = CliRunner().invoke(app, ["scan", str(PROJECT), "--sarif", str(out)])
    assert out.is_file(), result.output
    payload = json.loads(out.read_text("utf-8"))
    validate(payload)
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert uri["uri"] == "tests/fixtures/uv/tests-break/uv.lock"  # relative to the repo root
