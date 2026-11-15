"""The `scan` pipeline: detect -> collect -> merge -> annotate -> filter."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from vulnpilot.config import Config, IgnoreRule
from vulnpilot.detect import detect_project
from vulnpilot.lockgraph import load_graph, lock_versions
from vulnpilot.models import Finding, Project, Severity
from vulnpilot.proc import Runner
from vulnpilot.sources.imports import load_import
from vulnpilot.sources.merge import annotate, merge_findings
from vulnpilot.sources.osv import OsvSource


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "vulnpilot"


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


@dataclass
class ScanResult:
    project: Project
    run_id: str
    raw_dir: Path
    findings: list[Finding]
    """Every merged finding, sorted most severe first."""
    shown: list[Finding] = field(default_factory=list)
    """Findings at or above the threshold and not ignored."""
    ignored: list[tuple[Finding, IgnoreRule]] = field(default_factory=list)
    below_threshold: list[Finding] = field(default_factory=list)
    expired_rules: list[IgnoreRule] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    imports: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def sort_key(f: Finding) -> tuple[int, str, float, str]:
    """Most severe first; a package's rows stay together. KEV / EPSS join in Stage 5."""
    return (-f.severity.rank, f.package, -(f.cvss or 0.0), f.advisory_id)


EPSS_LIKELY = 0.1
"""EPSS probability at or above which a finding counts as likely to be exploited."""


def gate_severity(f: Finding) -> Severity:
    """Severity used for the threshold: an unrated finding counts as HIGH until rated."""
    return Severity.HIGH if f.severity is Severity.UNKNOWN else f.severity


def always_fix(f: Finding) -> bool:
    """Known or likely exploitation outranks the severity threshold."""
    return f.in_kev or (f.epss or 0.0) >= EPSS_LIKELY


def _matching_rule(f: Finding, rules: list[IgnoreRule]) -> IgnoreRule | None:
    ids = set(f.aliases)
    return next((r for r in rules if r.id in ids), None)


def apply_filters(
    result: ScanResult,
    cfg: Config,
    only: set[Severity] | None = None,
    today: date | None = None,
) -> None:
    today = today or date.today()
    active = [r for r in cfg.ignore if not r.is_expired(today)]
    result.expired_rules = [r for r in cfg.ignore if r.is_expired(today)]
    for f in result.findings:
        rule = _matching_rule(f, active)
        if rule is not None:
            result.ignored.append((f, rule))
        elif not always_fix(f) and (
            (only is not None and gate_severity(f) not in only)
            or (only is None and gate_severity(f).rank < cfg.threshold.rank)
        ):
            result.below_threshold.append(f)
        else:
            result.shown.append(f)


def run_scan(
    path: Path,
    cfg: Config,
    only: set[Severity] | None = None,
    run: Runner | None = None,
    today: date | None = None,
    imports: list[Path] | None = None,
) -> ScanResult:
    project = detect_project(path, base_branch=cfg.pr.base_branch)
    run_id = new_run_id()
    raw = cache_dir() / "runs" / run_id
    return scan_project(project, cfg, run_id, raw, only, run, today, imports=imports)


def resolve_imports(project_root: Path, cfg: Config, extra: list[Path] | None) -> list[Path]:
    """``imports:`` from vulnpilot.yml (relative to the project) plus --import files."""
    paths = [p if p.is_absolute() else project_root / p for p in cfg.imports]
    paths += [p.resolve() for p in extra or []]
    return list(dict.fromkeys(p.resolve() for p in paths))


def scan_project(
    project: Project,
    cfg: Config,
    run_id: str,
    raw_dir: Path,
    only: set[Severity] | None = None,
    run: Runner | None = None,
    today: date | None = None,
    *,
    imports: list[Path] | None = None,
) -> ScanResult:
    """Collect, merge, annotate and filter findings for an already-detected project."""
    osv = OsvSource(raw_dir, run=run)
    collected = osv.collect(project)
    warnings: list[str] = []
    imported_versions: dict[str, str] = {}
    if imports:
        lock = lock_versions(project.lockfile)
        for path in imports:
            imp = load_import(path, lock)
            collected += imp.findings
            warnings += imp.warnings
            if imp.tool_version:
                imported_versions[imp.tool] = imp.tool_version
    findings = merge_findings(collected)
    findings = annotate(findings, load_graph(project))
    findings.sort(key=sort_key)
    result = ScanResult(
        project=project,
        run_id=run_id,
        raw_dir=raw_dir,
        findings=findings,
        imports=list(imports or []),
        warnings=warnings,
    )
    result.tool_versions.update(imported_versions)
    version = next((h.tool_version for f in findings for h in f.sources if h.tool_version), None)
    if version:
        result.tool_versions["osv-scanner"] = version
    apply_filters(result, cfg, only, today)
    return result
