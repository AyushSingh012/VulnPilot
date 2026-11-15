from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnpilot import doctor
from vulnpilot.cli import app
from vulnpilot.models import ExitCode

runner = CliRunner()


def checks(ok: bool) -> list[doctor.CheckResult]:
    return [
        doctor.CheckResult("osv-scanner", ok, True, "2.2.3" if ok else None, "x"),
        doctor.CheckResult("uv", True, True, "0.11.6", "x"),
    ]


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "vulnpilot" in result.output


@pytest.mark.parametrize(("ok", "code"), [(True, ExitCode.OK), (False, ExitCode.ERROR)])
def test_doctor_exit_code(monkeypatch: pytest.MonkeyPatch, ok: bool, code: ExitCode) -> None:
    monkeypatch.setattr(doctor, "run_checks", lambda **_: checks(ok))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == code
    assert "osv-scanner" in result.output


def test_bad_config_exits_2(tmp_path: Path) -> None:
    (tmp_path / "vulnpilot.yml").write_text("unknown_key: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.ERROR
    assert "unknown_key" in result.output
