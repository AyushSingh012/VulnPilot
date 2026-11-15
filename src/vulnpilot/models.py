"""Core data models. These are the stable part of VulnPilot: later versions build on them."""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Literal

from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict, Field


class ExitCode(IntEnum):
    OK = 0
    """Nothing at or above the severity threshold remains."""
    FINDINGS_REMAIN = 1
    """Findings remain, or an upgrade introduced a new finding."""
    ERROR = 2
    """A tool or config error, or tests already fail before any change."""


class Severity(StrEnum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Bucket a CVSS 0-10 score the standard way."""
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.UNKNOWN


_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FixStatus(StrEnum):
    FIXED_AND_VALIDATED = "FIXED_AND_VALIDATED"
    FIXED_NOT_TESTED = "FIXED_NOT_TESTED"
    FIXED_BUT_TESTS_FAILED = "FIXED_BUT_TESTS_FAILED"
    STILL_PRESENT = "STILL_PRESENT"
    NO_SAFE_FIX = "NO_SAFE_FIX"
    FIXED_IN_SOURCE = "FIXED_IN_SOURCE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    INTRODUCED = "INTRODUCED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"

    @property
    def counts_as_fixed(self) -> bool:
        return self in {FixStatus.FIXED_AND_VALIDATED, FixStatus.FIXED_NOT_TESTED}


Manager = Literal["uv", "poetry"]
UpgradeMethod = Literal["lock-upgrade", "raise-bound", "constraint", "poetry-update", "poetry-add"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")


class Project(_Model):
    root: Path
    """The worktree for ``fix``; the given path for ``scan``."""
    manager: Manager
    lockfile: Path
    commit_sha: str | None = None
    base_branch: str = "main"


class SourceHit(_Model):
    """One scanner's report of a finding."""

    source: str
    """"osv" or "import:<file>"."""
    tool: str
    """"osv-scanner", "trivy" or "wiz"."""
    tool_version: str | None = None
    target: str = "source"
    """"source" (repo/lockfile) or "image:<ref>"."""
    raw_id: str
    """The advisory ID that tool used."""
    severity: Severity = Severity.UNKNOWN
    installed_version: str
    """As that tool saw it; an image can be older than the lockfile."""
    fixed_version: str | None = None


def normalize_package(name: str) -> str:
    """PEP 503 name normalization: ``Jinja2`` and ``jinja2`` are the same package."""
    return str(canonicalize_name(name))


def finding_key(ecosystem: str, package: str, aliases: list[str]) -> str:
    """Stable identity for a finding: ecosystem | package | alias group. Never the version.

    The alias group is represented by its lowest-sorted ID. Comparisons between scans
    must still match on alias *overlap* (see the rescan step), because an advisory can
    gain a new alias, such as a CVE assigned after the GHSA, between runs.
    """
    if not aliases:
        raise ValueError("a finding needs at least one advisory ID")
    return f"{ecosystem}|{normalize_package(package)}|{min(aliases)}"


class Finding(_Model):
    key: str
    """ecosystem|package|alias group; see :func:`finding_key`."""
    advisory_id: str
    """Preferred CVE, else GHSA / PYSEC id."""
    aliases: list[str]
    """The alias group: all IDs for the same issue."""
    ecosystem: str
    """"PyPI", or the OS package type ("apk", "deb")."""
    package: str
    installed_version: str
    """Version in the lockfile (or the image, if the package is not in the lockfile)."""
    fixed_versions: list[str] = Field(default_factory=list)
    in_lockfile: bool = True
    is_direct: bool = False
    dev_only: bool = False
    """Reached only through dependency groups (dev), not at runtime."""
    dependency_paths: list[list[str]] = Field(default_factory=list)
    """Each path: app -> parent -> vulnerable package."""
    severity: Severity = Severity.UNKNOWN
    """Highest across sources."""
    cvss: float | None = None
    epss: float | None = None
    in_kev: bool = False
    references: list[str] = Field(default_factory=list)
    sources: list[SourceHit] = Field(default_factory=list)


class Upgrade(_Model):
    """One planned package change."""

    package: str
    from_version: str
    to_version: str
    """Lowest non-yanked version that fixes all of this package's advisories."""
    method: UpgradeMethod
    finding_keys: list[str]


class ValidationResult(_Model):
    ran: bool
    """False when ``validate.test`` is ``none``."""
    passed: bool | None = None
    failed_tests: list[str] = Field(default_factory=list)
    """Test names only, never log output."""
    log_path: str | None = None
    """The full log stays on disk."""


class FixResult(_Model):
    finding_key: str
    status: FixStatus
    upgrade: Upgrade | None = None
    note: str = ""
    """Why, in plain words."""


class RunReport(_Model):
    run_id: str
    repo: str
    commit_sha: str | None
    started_at: datetime
    tool_versions: dict[str, str] = Field(default_factory=dict)
    findings_before: list[Finding] = Field(default_factory=list)
    findings_after: list[Finding] = Field(default_factory=list)
    results: list[FixResult] = Field(default_factory=list)
    baseline: ValidationResult | None = None
    final: ValidationResult | None = None
    pr_url: str | None = None
