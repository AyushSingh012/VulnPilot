from datetime import date
from pathlib import Path

import pytest

from vulnpilot.config import Config, ConfigError, load_config
from vulnpilot.models import Severity


def write(tmp_path: Path, text: str) -> Path:
    (tmp_path / "vulnpilot.yml").write_text(text, encoding="utf-8")
    return tmp_path


def test_defaults_when_file_missing(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg == Config()
    assert cfg.threshold is Severity.LOW
    assert cfg.allow_major_upgrades is False
    assert cfg.pr.branch == "vulnpilot/security-fixes"
    assert cfg.validation.install_command("uv") == "uv sync --frozen"
    assert cfg.validation.test_command("uv") == "uv run pytest -q"
    assert cfg.validation.install_command("poetry") == "poetry sync"
    assert cfg.validation.tests_enabled


def test_empty_file_gives_defaults(tmp_path: Path) -> None:
    assert load_config(write(tmp_path, "")) == Config()


def test_full_file(tmp_path: Path) -> None:
    cfg = load_config(
        write(
            tmp_path,
            """
imports: [scans/wiz-image.json]
severity_threshold: high
allow_major_upgrades: true
validate:
  test: "docker compose run --rm tests"
  timeout_minutes: 30
ignore:
  - id: GHSA-xxxx-xxxx-xxxx
    reason: dev-only tool, not shipped
    expires: 2027-03-01
pr:
  base_branch: develop
  reviewers: [someone]
""",
        )
    )
    assert cfg.imports == [Path("scans/wiz-image.json")]
    assert cfg.threshold is Severity.HIGH
    assert cfg.validation.test_command("uv") == "docker compose run --rm tests"
    assert cfg.validation.timeout_minutes == 30
    assert cfg.ignore[0].is_expired(date(2027, 3, 2))
    assert not cfg.ignore[0].is_expired(date(2027, 3, 1))
    assert cfg.pr.base_branch == "develop"
    assert cfg.pr.labels == ["security", "dependencies"]


def test_tests_can_be_turned_off(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, "validate:\n  test: none\n"))
    assert cfg.validation.test_command("uv") is None
    assert not cfg.validation.tests_enabled


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("sources: [osv, trivy]\n", "sources"),
        ("validate:\n  tset: pytest\n", "validate.tset"),
        ("ignore:\n  - id: X\n    expires: 2027-01-01\n", "reason"),
        ("severity_threshold: SEVERE\n", "severity_threshold"),
        ("- just\n- a list\n", "mapping"),
        ("validate: [\n", "not valid YAML"),
    ],
)
def test_bad_config_is_a_clear_error(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, text))
