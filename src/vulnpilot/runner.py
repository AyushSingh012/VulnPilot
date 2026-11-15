"""The `fix` pipeline.

detect -> worktree -> PR-branch check -> scan -> plan -> resolve -> baseline test ->
apply + test + isolate breakers -> changed-files check -> rescan -> classify ->
commit -> push -> open or update the PR (or, with --no-push, a local branch + body file).
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
from vulnpilot.git_ops import (
    TRAILER,
    BranchState,
    GitError,
    branch_state,
    commit,
    foreign_error,
    has_remote,
    push,
    repo_slug,
    same_change,
    set_local_branch,
)
from vulnpilot.github import GhCli, GitHubError, PRHost, PullRequest
from vulnpilot.isolate import isolate_breakers
from vulnpilot.lockgraph import load_graph
from vulnpilot.models import (
    ExitCode,
    FixStatus,
    RunReport,
    Severity,
    Upgrade,
    ValidationResult,
)
from vulnpilot.plan import Plan, build_plan
from vulnpilot.pr_body import BodyInput, render
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
    branch: str = ""
    pr_action: str = "none"
    """created | updated | unchanged | local | none"""
    pr: PullRequest | None = None
    pr_note: str = ""
    commit_sha: str | None = None
    pr_title: str = ""
    body_path: Path | None = None
    warnings: list[str] = field(default_factory=list)


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
    push_pr: bool = True,
    keep_worktree: bool = False,
    host: PRHost | None = None,
    index: ReleaseIndex | None = None,
    today: date | None = None,
) -> FixOutcome:
    """Run the loop; then commit and open or update the PR (``push_pr``) or a local branch.

    ``host`` is where the PR lives; by default gh on the repo behind ``origin``.
    """
    origin = detect_project(path, base_branch=cfg.pr.base_branch)
    if origin.manager != "uv":
        raise FixError("fixing Poetry projects is not built yet (Stage 6); `scan` works")
    run_id = new_run_id()
    run_dir = cache_dir() / "runs" / run_id
    env = tool_env(run_dir)
    started = datetime.now(UTC)

    with worktree(origin.root, cfg.pr.base_branch, run_dir / "worktree", keep_worktree) as wt:
        state: BranchState | None = None
        if not dry_run:
            host, state = _preflight(wt, cfg, push_pr, host)
        outcome = _fix_in_worktree(
            wt, cfg, only, run_id, run_dir, env, started, dry_run, index, today
        )
        outcome.worktree_path = wt.path if keep_worktree else None
        outcome.ref = wt.ref
        outcome.run_dir = run_dir
        outcome.display_name = wt.project_rel or origin.root.name
        outcome.branch = cfg.pr.branch
        if state is not None:
            _publish(outcome, wt, cfg, state, host if push_pr else None)
        return outcome


def _preflight(
    wt: Worktree, cfg: Config, push_pr: bool, host: PRHost | None
) -> tuple[PRHost | None, BranchState]:
    """Before any slow work: can we push, and is the PR branch ours to rebuild?"""
    branch = cfg.pr.branch
    if not push_pr:
        state = branch_state(wt.repo_root, branch, wt.commit_sha, remote=False)
        if state.foreign:
            raise foreign_error(state, "local")
        return None, state
    if not has_remote(wt.repo_root):
        raise GitError("the repo has no 'origin' remote to push to; use --no-push")
    if host is None:
        gh = GhCli(cfg.pr.repo or repo_slug(wt.repo_root), cfg.pr.gh_user)
        gh.check_access()
        host = gh
    state = branch_state(wt.repo_root, branch, wt.commit_sha, remote=True, env=host.push_env())
    if state.foreign:
        raise foreign_error(state, "origin")
    return host, state


def _commit_message(outcome: FixOutcome, report: RunReport, title: str) -> str:
    by_key = {f.key: f for f in report.findings_before}
    lines = [title, ""]
    for u in outcome.kept:
        ids = [
            by_key[r.finding_key].advisory_id
            for r in report.results
            if r.status.counts_as_fixed and r.upgrade and r.upgrade.package == u.package
        ]
        if ids:
            lines.append(f"- {u.package} {u.from_version} -> {u.to_version}: {', '.join(ids)}")
    return "\n".join([*lines, "", f"{TRAILER}: {report.run_id}"])


def _publish(
    outcome: FixOutcome, wt: Worktree, cfg: Config, state: BranchState, host: PRHost | None
) -> None:
    """Commit the kept upgrades, then push and open / update the PR (or a local branch)."""
    report = outcome.report
    if report is None or outcome.run_dir is None:
        return
    introduced = [r for r in report.results if r.status is FixStatus.INTRODUCED]
    if introduced:
        outcome.pr_note = (
            f"No PR: the upgrades bring in {len(introduced)} new finding(s); see INTRODUCED above."
        )
        return
    if not any(r.status.counts_as_fixed for r in report.results) or not outcome.changed:
        outcome.pr_note = "No PR: nothing was fixed, so there is nothing to commit."
        if host is not None and (pr := host.find_open(state.name)) is not None:
            outcome.pr = pr
            outcome.pr_note += f" The open VulnPilot PR #{pr.number} was left as is."
        return

    title, text = render(
        BodyInput(report=report, base_ref=wt.ref, pyproject_changes=outcome.pyproject_changes)
    )
    body_path = outcome.run_dir / "pr-body.md"
    body_path.write_text(text, "utf-8")
    outcome.body_path = body_path
    outcome.pr_title = title
    sha = commit(wt.path, sorted(outcome.changed), _commit_message(outcome, report, title))
    outcome.commit_sha = sha

    if host is None:
        set_local_branch(wt.repo_root, state.name, sha)
        outcome.pr_action = "local"
        return

    if state.sha and same_change(wt.repo_root, state.sha, sha):
        outcome.pr_action = "unchanged"
        outcome.commit_sha = state.sha
    else:
        push(wt.repo_root, sha, state.name, state.sha, host.push_env())
    pushed = "" if outcome.pr_action == "unchanged" else f"'{state.name}' was pushed, but "
    try:
        pr = host.find_open(state.name)
        if pr is not None:
            host.update(pr, title, body_path)
            if outcome.pr_action != "unchanged":
                outcome.pr_action = "updated"
        else:
            pr = host.create(cfg.pr.base_branch, state.name, title, body_path)
            outcome.pr_action = "created"
            outcome.warnings += host.decorate(pr, cfg.pr.labels, cfg.pr.reviewers)
    except GitHubError as exc:
        raise GitHubError(pushed + str(exc)) from exc
    outcome.pr = pr
    report.pr_url = pr.url
    (outcome.run_dir / "report.json").write_text(report.model_dump_json(indent=2), "utf-8")


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
        extras=before.below_threshold,
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
    # An import finding whose lockfile version is now fixed is gone, as far as the PR goes.
    present = [f for f in after.findings if not f.fixed_in_source]
    present_keys = {f.key for f in present}
    results = classify(
        before.shown,
        before.ignored,
        before.below_threshold,
        plan,
        kept,
        breakers,
        blocked,
        before.findings,
        [f for f in after.shown if f.key in present_keys],
        tests_ran=validator.tests_enabled,
        after_all=present,
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
