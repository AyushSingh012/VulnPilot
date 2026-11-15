import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import ALL_FIXTURES, FIXTURES, fake_osv_runner, fixture_dir, fixture_spec
from vulnpilot import scanner
from vulnpilot.cli import app
from vulnpilot.config import Config, IgnoreRule
from vulnpilot.models import ExitCode, Finding, Project, Severity, finding_key
from vulnpilot.scanner import run_scan

cli = CliRunner()


def scan(
    name: str, cfg: Config | None = None, only: set[Severity] | None = None
) -> scanner.ScanResult:
    return run_scan(
        fixture_dir(name),
        cfg or Config(severity_threshold="LOW"),
        only,
        run=fake_osv_runner(name),
        today=date(2026, 11, 15),
    )


@pytest.mark.parametrize("d", ALL_FIXTURES, ids=lambda d: d.name)
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


def _result(*findings: Finding) -> scanner.ScanResult:
    project = Project(root=Path(), manager="uv", lockfile=Path("uv.lock"))
    return scanner.ScanResult(project, "r", Path(), list(findings))


def _f(cve: str, severity: Severity, *, kev: bool = False, epss: float | None = None) -> Finding:
    return Finding(
        key=finding_key("PyPI", "demo", [cve]),
        advisory_id=cve,
        aliases=[cve],
        ecosystem="PyPI",
        package="demo",
        installed_version="1.0",
        severity=severity,
        in_kev=kev,
        epss=epss,
    )


def test_default_threshold_is_high_and_unrated_counts_as_high() -> None:
    crit, high, med, unrated = (
        _f("CVE-1", Severity.CRITICAL),
        _f("CVE-2", Severity.HIGH),
        _f("CVE-3", Severity.MEDIUM),
        _f("CVE-4", Severity.UNKNOWN),
    )
    result = _result(crit, high, med, unrated)
    scanner.apply_filters(result, Config())
    assert [f.advisory_id for f in result.shown] == ["CVE-1", "CVE-2", "CVE-4"]
    assert result.below_threshold == [med]
    only = _result(med, unrated)
    scanner.apply_filters(only, Config(), only={Severity.HIGH})
    assert only.shown == [unrated]


def test_known_or_likely_exploited_ignores_the_threshold() -> None:
    kev = _f("CVE-1", Severity.LOW, kev=True)
    likely = _f("CVE-2", Severity.MEDIUM, epss=0.42)
    unlikely = _f("CVE-3", Severity.MEDIUM, epss=0.01)
    result = _result(kev, likely, unlikely)
    scanner.apply_filters(result, Config())
    assert result.shown == [kev, likely] and result.below_threshold == [unlikely]


def test_cli_min_severity_overrides_the_config(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_runner(monkeypatch, "transitive")
    path = str(FIXTURES / "uv" / "transitive")
    default = cli.invoke(app, ["scan", path])
    lowered = cli.invoke(app, ["scan", path, "--min-severity", "medium"])
    assert "below threshold" in default.output
    assert "below threshold" not in lowered.output
    bad = cli.invoke(app, ["scan", path, "--min-severity", "SEVERE"])
    assert bad.exit_code == ExitCode.ERROR and "--min-severity" in bad.output
