"""``vulnpilot doctor``: check the external tools VulnPilot drives.

Only exit codes and version strings are read. The output of ``gh auth status`` is never
printed or stored, so no account details or token fragments leak into logs.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from vulnpilot import proc
from vulnpilot.proc import ProcResult, Runner, ToolNotFoundError, ToolTimeoutError

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version_cmd: tuple[str, ...]
    required: bool
    purpose: str
    required_major: int | None = None
    install_hint: str = ""


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "osv-scanner",
        ("osv-scanner", "--version"),
        required=True,
        purpose="finds vulnerable packages in the lockfile",
        required_major=2,
        install_hint="install the pinned v2 release: https://github.com/google/osv-scanner/releases",
    ),
    ToolSpec(
        "uv",
        ("uv", "--version"),
        required=True,
        purpose="locks, upgrades and installs uv projects",
        install_hint="https://docs.astral.sh/uv/getting-started/installation/",
    ),
    ToolSpec(
        "poetry",
        ("poetry", "--version"),
        required=False,
        purpose="needed only for Poetry projects",
        install_hint="https://python-poetry.org/docs/#installation",
    ),
    ToolSpec(
        "git",
        ("git", "--version"),
        required=True,
        purpose="worktree, branch and commit",
    ),
    ToolSpec(
        "gh",
        ("gh", "--version"),
        required=True,
        purpose="opens and updates the PR",
        install_hint="https://cli.github.com/",
    ),
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    required: bool
    version: str | None
    detail: str


def _default_runner(cmd: Sequence[str]) -> ProcResult:
    return proc.run(cmd, timeout=30)


def parse_version(text: str) -> str | None:
    match = _VERSION_RE.search(text)
    return ".".join(match.groups()) if match else None


def check_tool(spec: ToolSpec, run: Runner = _default_runner) -> CheckResult:
    def missing(detail: str) -> CheckResult:
        hint = f" ({spec.install_hint})" if spec.install_hint else ""
        return CheckResult(spec.name, False, spec.required, None, f"{detail}{hint}")

    try:
        result = run(spec.version_cmd)
    except ToolNotFoundError:
        return missing("not found on PATH")
    except ToolTimeoutError:
        return missing("did not answer --version")
    if not result.ok:
        return missing(f"'{' '.join(spec.version_cmd)}' exited with {result.returncode}")

    version = parse_version(result.stdout + result.stderr)
    if version is None:
        return CheckResult(spec.name, False, spec.required, None, "could not read its version")
    if spec.required_major is not None and int(version.split(".")[0]) != spec.required_major:
        return CheckResult(
            spec.name,
            False,
            spec.required,
            version,
            f"version {spec.required_major}.x is required",
        )
    return CheckResult(spec.name, True, spec.required, version, spec.purpose)


def check_gh_login(run: Runner = _default_runner) -> CheckResult:
    try:
        result = run(("gh", "auth", "status"))
    except (ToolNotFoundError, ToolTimeoutError):
        return CheckResult("gh login", False, True, None, "gh is not available")
    if result.ok:
        return CheckResult("gh login", True, True, None, "logged in")
    return CheckResult("gh login", False, True, None, "not logged in; run: gh auth login")


def run_checks(run: Runner = _default_runner) -> list[CheckResult]:
    results = [check_tool(spec, run) for spec in TOOLS]
    gh = next(r for r in results if r.name == "gh")
    if gh.ok:
        results.append(check_gh_login(run))
    return results


def all_required_ok(results: list[CheckResult]) -> bool:
    return all(r.ok for r in results if r.required)
