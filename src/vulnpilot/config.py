"""Load ``vulnpilot.yml``. Every key is optional; unknown keys are an error.

Test and install commands come only from this local file, never from a remote source.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from vulnpilot.models import Manager, Severity

CONFIG_FILENAME = "vulnpilot.yml"
NO_TESTS = "none"

_DEFAULT_INSTALL: dict[Manager, str] = {"uv": "uv sync --frozen", "poetry": "poetry sync"}
_DEFAULT_TEST: dict[Manager, str] = {"uv": "uv run pytest -q", "poetry": "poetry run pytest -q"}


class ConfigError(Exception):
    """vulnpilot.yml is missing required structure or has unknown keys."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ValidateConfig(_Strict):
    install: str | None = None
    """None = the manager's default (``uv sync --frozen`` / ``poetry sync``)."""
    test: str | None = None
    """None = the manager's default; ``"none"`` = do not run tests (FIXED_NOT_TESTED)."""
    timeout_minutes: int = Field(default=15, gt=0)
    retries: int = Field(default=1, ge=0, le=3)
    isolate_breakers: bool = True

    def install_command(self, manager: Manager) -> str:
        return self.install or _DEFAULT_INSTALL[manager]

    def test_command(self, manager: Manager) -> str | None:
        """The test command, or None when tests are turned off."""
        cmd = self.test or _DEFAULT_TEST[manager]
        return None if cmd.strip().lower() == NO_TESTS else cmd

    @property
    def tests_enabled(self) -> bool:
        return (self.test or "").strip().lower() != NO_TESTS


class IgnoreRule(_Strict):
    id: str
    reason: str = Field(min_length=1)
    expires: date

    def is_expired(self, today: date) -> bool:
        return today > self.expires


class PRConfig(_Strict):
    base_branch: str = "main"
    branch: str = "vulnpilot/security-fixes"
    reviewers: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=lambda: ["security", "dependencies"])
    gh_user: str | None = None
    """gh account to open the PR with (its token is used for VulnPilot's commands only).
    None = the account active in gh."""
    repo: str | None = Field(default=None, pattern=r"^[\w.-]+/[\w.-]+$")
    """GitHub ``owner/name``; None = read it from the ``origin`` remote."""


class Config(_Strict):
    imports: list[Path] = Field(default_factory=list)
    severity_threshold: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    """Fix findings at or above this. Unrated findings count as HIGH; KEV-listed or likely
    exploited (EPSS) findings are always included."""
    allow_major_upgrades: bool = False
    osv_offline: bool = True
    """Match the lockfile against a local copy of the OSV database (downloaded and kept
    up to date in the cache) instead of sending package names and versions to osv.dev."""
    enrich: bool = True
    """Look up CISA KEV and FIRST EPSS for each CVE (only CVE IDs are sent)."""
    # "validate" would shadow BaseModel.validate, so the attribute has another name.
    validation: ValidateConfig = Field(default_factory=ValidateConfig, alias="validate")
    ignore: list[IgnoreRule] = Field(default_factory=list)
    pr: PRConfig = Field(default_factory=PRConfig)

    @field_validator("severity_threshold", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @property
    def threshold(self) -> Severity:
        return Severity(self.severity_threshold)


def load_config(project_root: Path, file: Path | None = None) -> Config:
    """Read ``file``, else ``<project_root>/vulnpilot.yml`` if it exists, else the defaults."""
    path = file or project_root / CONFIG_FILENAME
    if file is not None and not file.is_file():
        raise ConfigError(f"{file}: no such config file")
    if not path.is_file():
        return Config()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML ({exc})") from exc
    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping of keys at the top level")
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ConfigError(f"{path}: {problems}") from exc
