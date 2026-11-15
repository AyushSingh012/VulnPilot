"""Human-readable scan output."""

from __future__ import annotations

from collections import Counter

from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.table import Table

from vulnpilot.models import Finding, Severity
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
