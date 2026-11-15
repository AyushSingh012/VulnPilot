import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import FIXTURES, UV_FIXTURES, fake_osv_runner, fixture_spec
from vulnpilot import scanner
from vulnpilot.cli import app
from vulnpilot.config import Config, IgnoreRule
from vulnpilot.models import ExitCode, Severity
from vulnpilot.scanner import run_scan

cli = CliRunner()


def scan(
    name: str, cfg: Config | None = None, only: set[Severity] | None = None
) -> scanner.ScanResult:
    return run_scan(
        FIXTURES / "uv" / name,
        cfg or Config(),
        only,
        run=fake_osv_runner(name),
        today=date(2026, 11, 15),
    )


@pytest.mark.parametrize("d", UV_FIXTURES, ids=lambda d: d.name)
def test_every_fixture_matches_its_expected_scan(d: Path) -> None:
    result = scan(d.name)
    for exp in fixture_spec(d)["expected"]["scan"]:
        [hit] = [
            f for f in result.shown if f.package == exp["package"] and exp["advisory"] in f.aliases
        ]
        assert hit.installed_version == exp["installed"]
        if "direct" in exp:
            assert hit.is_direct is exp["direct"]
        if "path" in exp:
            assert exp["path"] in hit.dependency_paths


def test_sorted_most_severe_first() -> None:
    ranks = [f.severity.rank for f in scan("transitive").shown]
    assert ranks == sorted(ranks, reverse=True)


def test_ignore_rule_hides_by_any_alias() -> None:
    rule = IgnoreRule(id="GHSA-9wx4-h78v-vm56", reason="accepted", expires=date(2027, 1, 1))
    result = scan("direct-pinned", Config(ignore=[rule]))
    assert [f.advisory_id for f, _ in result.ignored] == ["CVE-2024-35195"]
    assert all("CVE-2024-35195" not in f.aliases for f in result.shown)


def test_expired_rule_does_not_hide() -> None:
    rule = IgnoreRule(id="CVE-2024-35195", reason="old", expires=date(2026, 1, 1))
    result = scan("direct-pinned", Config(ignore=[rule]))
    assert result.ignored == []
    assert result.expired_rules == [rule]


def test_threshold_and_explicit_severity() -> None:
    high = scan("transitive", Config(severity_threshold="HIGH"))
    assert high.shown and all(f.severity.rank >= Severity.HIGH.rank for f in high.shown)
    assert high.below_threshold
    only_medium = scan("transitive", only={Severity.MEDIUM})
    assert only_medium.shown and {f.severity for f in only_medium.shown} == {Severity.MEDIUM}


def test_raw_output_lands_in_cache(isolated_cache: Path) -> None:
    result = scan("transitive")
    assert result.raw_dir.is_relative_to(isolated_cache)
    assert (result.raw_dir / "osv-scanner.json").is_file()
    assert result.tool_versions == {"osv-scanner": "2.7.1"}


def _patch_runner(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    original = scanner.run_scan

    def patched(
        path: Path, cfg: Config, only: set[Severity] | None = None, **_: object
    ) -> scanner.ScanResult:
        return original(path, cfg, only, run=fake_osv_runner(name))

    monkeypatch.setattr("vulnpilot.cli.run_scan", patched)


def test_cli_scan_exit_1_and_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_runner(monkeypatch, "transitive")
    out = tmp_path / "report.json"
    result = cli.invoke(app, ["scan", str(FIXTURES / "uv" / "transitive"), "--json", str(out)])
    assert result.exit_code == ExitCode.FINDINGS_REMAIN, result.output
    assert "urllib3" in result.output
    data = json.loads(out.read_text("utf-8"))
    assert data["project"] == "transitive"
    assert all(f["package"] == "urllib3" for f in data["findings"])


def test_cli_scan_exit_0_when_everything_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_runner(monkeypatch, "direct-pinned")
    result = cli.invoke(
        app, ["scan", str(FIXTURES / "uv" / "direct-pinned"), "--severity", "CRITICAL"]
    )
    assert result.exit_code == ExitCode.OK, result.output
    assert "No findings" in result.output


@pytest.mark.parametrize(
    ("args", "match"),
    [
        (["--severity", "SEVERE"], "unknown severity"),
        (["--sarif", "x.sarif"], "Stage 5"),
    ],
)
def test_cli_scan_option_errors(args: list[str], match: str) -> None:
    result = cli.invoke(app, ["scan", str(FIXTURES / "uv" / "transitive"), *args])
    assert result.exit_code == ExitCode.ERROR
    assert match in result.output


def test_cli_scan_not_a_project(tmp_path: Path) -> None:
    result = cli.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.ERROR
    assert "no pyproject.toml" in result.output
