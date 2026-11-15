"""Human-readable scan output."""

from __future__ import annotations

from collections import Counter

from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.table import Table

from vulnpilot.models import Finding, FixStatus, Severity
from vulnpilot.runner import FixOutcome
from vulnpilot.scanner import ScanResult

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}


def _major(v: str) -> int | None:
    try:
        return Version(v).major
    except InvalidVersion:
        return None


def fix_label(f: Finding) -> str:
    if not f.fixed_versions:
        return "none"
    target = f.fixed_versions[0]
    cur, new = _major(f.installed_version), _major(target)
    if cur is not None and new is not None and new > cur:
        return f"{target} (major)"
    return target


def kind_label(f: Finding) -> str:
    kind = "direct" if f.is_direct else "transitive"
    return f"{kind}, dev" if f.dev_only else kind


def via_label(f: Finding) -> str:
    """For transitive packages: the shortest chain of parents, without the project itself."""
    if f.is_direct or not f.dependency_paths:
        return ""
    return " → ".join(f.dependency_paths[0][1:-1])


def render_scan(result: ScanResult, console: Console) -> None:
    rel = result.project.lockfile.name
    console.print(
        f"[bold]{result.project.root.name}[/bold] · {result.project.manager} · {rel}"
        + (f" · {result.project.commit_sha[:8]}" if result.project.commit_sha else "")
    )
    if result.shown:
        table = Table(show_lines=False, header_style="bold")
        for col in ("Severity", "Package", "Installed", "Advisory", "Fixed in", "Type"):
            table.add_column(col, no_wrap=True)
        show_via = any(via_label(f) for f in result.shown)
        if show_via:
            table.add_column("Via", overflow="fold", min_width=8)
        for f in result.shown:
            row = [
                f"[{_STYLE[f.severity]}]{f.severity.value}[/]",
                f.package,
                f.installed_version,
                f.advisory_id,
                fix_label(f),
                kind_label(f),
            ]
            table.add_row(*row, *([via_label(f)] if show_via else []))
        console.print(table)

    counts = Counter(f.severity for f in result.shown)
    parts = [f"{counts[s]} {s.value.lower()}" for s in reversed(Severity) if counts[s]]
    packages = len({f.package for f in result.shown})

    def plural(n: int, word: str) -> str:
        return f"{n} {word}" + ("" if n == 1 else "s")

    summary = (
        f"{plural(len(result.shown), 'finding')} in {plural(packages, 'package')}"
        + (f" ({', '.join(parts)})" if parts else "")
        if result.shown
        else "No findings at or above the threshold."
    )
    extras = []
    if result.ignored:
        extras.append(f"{len(result.ignored)} ignored by config")
    if result.below_threshold:
        extras.append(f"{len(result.below_threshold)} below threshold")
    console.print(summary + (f" · {' · '.join(extras)}" if extras else ""))
    for rule in result.expired_rules:
        console.print(
            f"[yellow]Ignore rule for {rule.id} expired on {rule.expires}; "
            "it no longer hides that finding.[/yellow]"
        )
    console.print(f"[dim]Raw scanner output: {result.raw_dir}[/dim]")


_STATUS_STYLE = {
    FixStatus.FIXED_AND_VALIDATED: "green",
    FixStatus.FIXED_NOT_TESTED: "green",
    FixStatus.FIXED_BUT_TESTS_FAILED: "red",
    FixStatus.STILL_PRESENT: "red",
    FixStatus.NO_SAFE_FIX: "yellow",
    FixStatus.FIXED_IN_SOURCE: "cyan",
    FixStatus.OUT_OF_SCOPE: "cyan",
    FixStatus.INTRODUCED: "bold red",
    FixStatus.SKIPPED: "dim",
    FixStatus.ERROR: "bold red",
}


def render_plan(outcome: FixOutcome, console: Console) -> None:
    plan = outcome.plan
    if plan is None:
        return
    for warning in plan.warnings:
        console.print(f"[yellow]{warning}[/yellow]")
    resolvable = {u.package: u for u in outcome.resolvable}
    if plan.upgrades:
        table = Table(title="Planned upgrades", header_style="bold", title_justify="left")
        for col in ("Package", "From", "To", "How", "Fixes", "Left", "Resolves"):
            table.add_column(col, no_wrap=col != "Resolves", overflow="fold")
        for u in plan.upgrades:
            r = resolvable.get(u.package)
            how: str = r.method if r else u.method
            if r and r.parents:
                how += f" ({', '.join(r.parents)})"
            table.add_row(
                u.package,
                u.from_version,
                u.to_version,
                how,
                str(len(u.finding_keys)),
                str(len(u.unfixed_keys)) if u.unfixed_keys else "",
                "[green]yes[/green]"
                if r
                else f"[red]no[/red]: {outcome.blocked.get(u.package, '')}",
            )
        console.print(table)
    else:
        console.print("No upgrades to make.")
    if plan.no_fix:
        console.print(f"{len(plan.no_fix)} findings have no safe fix (details in the full run).")


def render_fix(outcome: FixOutcome, console: Console) -> None:
    scan = outcome.scan
    if scan is not None:
        console.print(
            f"[bold]{outcome.display_name or scan.project.root.name}[/bold] · "
            f"{scan.project.manager} · "
            f"worktree of {outcome.ref} @ {(scan.project.commit_sha or '')[:8]}"
        )
    if outcome.dry_run or outcome.report is None:
        render_plan(outcome, console)
        console.print("[dim]Dry run: nothing was tested or changed.[/dim]")
        return
    report = outcome.report
    by_key = {f.key: f for f in [*report.findings_before, *report.findings_after]}
    table = Table(header_style="bold")
    for col in ("Status", "Package", "Advisory", "Change", "Note"):
        table.add_column(col, no_wrap=col in ("Status", "Package", "Advisory"), overflow="fold")
    order = list(FixStatus)
    shown = [r for r in report.results if r.status is not FixStatus.SKIPPED]
    shown.sort(key=lambda r: (order.index(r.status), by_key[r.finding_key].package))
    for r in shown:
        f = by_key[r.finding_key]
        change = f"{r.upgrade.from_version} → {r.upgrade.to_version}" if r.upgrade else ""
        table.add_row(
            f"[{_STATUS_STYLE[r.status]}]{r.status.value}[/]",
            f.package,
            f.advisory_id,
            change,
            r.note,
        )
    console.print(table)
    counts = Counter(r.status for r in report.results)
    console.print(" · ".join(f"{n} {s.value}" for s, n in counts.items()))
    for pkg, changes in outcome.pyproject_changes.items():
        for old, new in changes:
            console.print(f"pyproject.toml ({pkg}): {old} → {new}")
    if outcome.changed:
        console.print(f"Changed files: {', '.join(outcome.changed)}")
    console.print(f"Test runs after the baseline: {outcome.test_runs}")
    if outcome.worktree_path:
        console.print(f"Worktree kept at {outcome.worktree_path}")
    render_publish(outcome, console)
    console.print(f"[dim]Run folder: {outcome.run_dir}[/dim]")


def render_publish(outcome: FixOutcome, console: Console) -> None:
    sha = (outcome.commit_sha or "")[:8]
    pr = outcome.pr
    if outcome.pr_action == "created" and pr:
        console.print(f"[green]Opened PR #{pr.number}[/green]: {pr.url}")
    elif outcome.pr_action == "updated" and pr:
        console.print(f"[green]Updated PR #{pr.number}[/green] ({sha} pushed): {pr.url}")
    elif outcome.pr_action == "unchanged" and pr:
        console.print(
            f"PR #{pr.number} already has these exact changes; description refreshed: {pr.url}"
        )
    elif outcome.pr_action == "local":
        console.print(
            f"--no-push: committed {sha} on local branch '{outcome.branch}'; nothing pushed."
        )
        console.print(f"PR title: {outcome.pr_title}")
        console.print(f"PR body: {outcome.body_path}")
    if outcome.pr_note:
        console.print(f"[yellow]{outcome.pr_note}[/yellow]")
    for warning in outcome.warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
