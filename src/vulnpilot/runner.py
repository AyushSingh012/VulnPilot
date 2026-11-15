"""The `fix` pipeline.

detect -> worktree -> scan -> plan -> resolve -> baseline test -> apply + test + isolate
breakers -> changed-files check -> rescan -> classify. (Commit / push / PR: Stage 4.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from vulnpilot.classify import classify, exit_code
from vulnpilot.config import Config
from vulnpilot.detect import detect_project
from vulnpilot.fixers.base import LockError
from vulnpilot.fixers.uv_fix import UvFixer
from vulnpilot.isolate import isolate_breakers
from vulnpilot.lockgraph import load_graph
from vulnpilot.models import ExitCode, RunReport, Severity, Upgrade, ValidationResult
from vulnpilot.plan import Plan, build_plan
from vulnpilot.pypi import PyPIIndex, ReleaseIndex
from vulnpilot.scanner import ScanResult, cache_dir, new_run_id, scan_project
from vulnpilot.validate import Validator, tool_env
from vulnpilot.worktree import Worktree, allowed_files, changed_files, worktree


class FixError(Exception):
    """The run cannot continue; nothing is changed (exit code 2)."""


@dataclass
class FixOutcome:
    exit_code: ExitCode
    report: RunReport | None = None
    plan: Plan | None = None
    resolvable: list[Upgrade] = field(default_factory=list)
    blocked: dict[str, str] = field(default_factory=dict)
    kept: list[Upgrade] = field(default_factory=list)
    scan: ScanResult | None = None
    changed: list[str] = field(default_factory=list)
    pyproject_changes: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    worktree_path: Path | None = None
    ref: str = ""
    run_dir: Path | None = None
    test_runs: int = 0
    dry_run: bool = False
    display_name: str = ""


def _priority(scan: ScanResult) -> dict[str, int]:
    """Most severe package first, so bisection keeps the important upgrades in context."""
    best: dict[str, int] = {}
    for f in scan.shown:
        best[f.package] = max(best.get(f.package, 0), f.severity.rank)
    return best


def run_fix(
    path: Path,
    cfg: Config,
    only: set[Severity] | None = None,
    *,
    dry_run: bool = False,
    keep_worktree: bool = False,
    index: ReleaseIndex | None = None,
    today: date | None = None,
) -> FixOutcome:
    origin = detect_project(path, base_branch=cfg.pr.base_branch)
    if origin.manager != "uv":
        raise FixError("fixing Poetry projects is not built yet (Stage 6); `scan` works")
    run_id = new_run_id()
    run_dir = cache_dir() / "runs" / run_id
    env = tool_env(run_dir)
    started = datetime.now(UTC)

    with worktree(origin.root, cfg.pr.base_branch, run_dir / "worktree", keep_worktree) as wt:
        outcome = _fix_in_worktree(
            wt, cfg, only, run_id, run_dir, env, started, dry_run, index, today
        )
        outcome.worktree_path = wt.path if keep_worktree else None
        outcome.ref = wt.ref
        outcome.run_dir = run_dir
        outcome.display_name = wt.project_rel or origin.root.name
        return outcome


def _fix_in_worktree(
    wt: Worktree,
    cfg: Config,
    only: set[Severity] | None,
    run_id: str,
    run_dir: Path,
    env: dict[str, str],
    started: datetime,
    dry_run: bool,
    index: ReleaseIndex | None,
    today: date | None,
) -> FixOutcome:
    project = detect_project(wt.project_dir, base_branch=cfg.pr.base_branch)
    project.commit_sha = wt.commit_sha
    before = scan_project(project, cfg, run_id, run_dir / "raw-before", only, today=today)
    graph = load_graph(project)
    plan = build_plan(
        before.shown,
        graph,
        (project.root / "pyproject.toml").read_text(encoding="utf-8"),
        project.lockfile,
        index or PyPIIndex(),
        cfg.allow_major_upgrades,
    )
    rank = _priority(before)
    plan.upgrades.sort(key=lambda u: (-rank.get(u.package, 0), u.package))

    fixer = UvFixer(project.root, graph, env)
    resolvable, blocked = fixer.resolve_each(plan.upgrades)
    if fixer.resolver_errors:
        (run_dir / "logs").mkdir(parents=True, exist_ok=True)
        (run_dir / "logs" / "resolver.log").write_text(
            "".join(f"{pkg}: {msg}\n" for pkg, msg in fixer.resolver_errors.items()), "utf-8"
        )
    outcome = FixOutcome(
        exit_code=ExitCode.OK, plan=plan, resolvable=resolvable, blocked=blocked, scan=before
    )
    if dry_run:
        outcome.dry_run = True
        return outcome

    validator = Validator(project.root, cfg.validation, project.manager, env, run_dir / "logs")
    fixer.restore()
    baseline = validator.run("baseline")
    if not baseline.passed:
        what = ", ".join(baseline.failed_tests) or "tests failed"
        raise FixError(
            f"tests already fail on {wt.ref} before any change ({what}); "
            f"fix them first. Log: {baseline.log_path}"
        )

    counter = 0

    def test(upgrades: list[Upgrade]) -> ValidationResult:
        nonlocal counter
        counter += 1
        try:
            fixer.apply(upgrades)
        except LockError:
            return ValidationResult(ran=False, passed=False, failed_tests=["<resolution failed>"])
        return validator.run(f"try-{counter:02d}")

    if validator.tests_enabled and cfg.validation.isolate_breakers:
        iso = isolate_breakers(resolvable, test)
        kept, breakers, final = iso.kept, iso.breakers, iso.final
        outcome.test_runs = iso.test_runs
    else:
        final = test(resolvable) if resolvable else None
        outcome.test_runs = 1 if resolvable else 0
        if final is not None and not final.passed:
            kept, breakers = [], {u.package: final for u in resolvable}
        else:
            kept, breakers = resolvable, {}

    fixer.apply(kept)  # leave exactly the kept upgrades in place
    outcome.kept = kept
    outcome.pyproject_changes = {
        k: v for k, v in fixer.pyproject_changes.items() if k in {u.package for u in kept}
    }
    changed = changed_files(wt)
    unexpected = sorted(set(changed) - allowed_files(wt, project.lockfile.name))
    if unexpected:
        fixer.restore()
        raise FixError(f"files other than pyproject.toml and the lockfile changed: {unexpected}")
    outcome.changed = changed

    after = scan_project(project, cfg, run_id, run_dir / "raw-after", only, today=today)
    results = classify(
        before.shown,
        before.ignored,
        before.below_threshold,
        plan,
        kept,
        breakers,
        blocked,
        before.findings,
        after.shown,
        tests_ran=validator.tests_enabled,
    )
    outcome.report = RunReport(
        run_id=run_id,
        repo=wt.repo_root.name,
        commit_sha=wt.commit_sha,
        started_at=started,
        tool_versions=before.tool_versions,
        findings_before=before.findings,
        findings_after=after.findings,
        results=results,
        baseline=baseline,
        final=final,
    )
    outcome.exit_code = exit_code(results)
    (run_dir / "report.json").write_text(outcome.report.model_dump_json(indent=2), "utf-8")
    return outcome
