"""Command-line entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from vulnpilot import __version__, doctor
from vulnpilot.config import Config, ConfigError, load_config
from vulnpilot.detect import DetectError
from vulnpilot.fixers.base import LockError
from vulnpilot.models import ExitCode, Severity
from vulnpilot.report.console import render_fix, render_scan
from vulnpilot.report.json_out import write_scan_json
from vulnpilot.runner import FixError, run_fix
from vulnpilot.scanner import run_scan
from vulnpilot.sources.base import SourceError
from vulnpilot.worktree import WorktreeError

app = typer.Typer(
    name="vulnpilot",
    help="Scan a Python project for vulnerable dependencies, fix them, test, rescan, open one PR.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

PathArg = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=False, resolve_path=True, help="Project directory."),
]
ImportOpt = Annotated[
    list[Path] | None,
    typer.Option(
        "--import",
        exists=True,
        dir_okay=False,
        help="Trivy or Wiz JSON file to merge in. Repeatable.",
    ),
]
SeverityOpt = Annotated[
    str | None,
    typer.Option("--severity", help="Only these severities, e.g. HIGH,CRITICAL."),
]


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"vulnpilot {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """VulnPilot v1."""


@app.command("doctor")
def doctor_cmd() -> None:
    """Check that osv-scanner, uv, poetry, git and gh are installed and gh is logged in."""
    results = doctor.run_checks()
    table = Table(title="vulnpilot doctor", show_lines=False)
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Detail")
    for r in results:
        if r.ok:
            status = "[green]ok[/green]"
        elif r.required:
            status = "[red]missing[/red]"
        else:
            status = "[yellow]optional[/yellow]"
        table.add_row(r.name, status, r.version or "-", r.detail)
    console.print(table)
    if not doctor.all_required_ok(results):
        err_console.print("[red]Some required tools are missing or not ready.[/red]")
        raise typer.Exit(ExitCode.ERROR)


def _fail(message: str) -> NoReturn:
    err_console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(ExitCode.ERROR)


def _load_config_or_exit(path: Path) -> Config:
    try:
        return load_config(path)
    except ConfigError as exc:
        err_console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(ExitCode.ERROR) from exc


def _not_yet(what: str, stage: str) -> NoReturn:
    err_console.print(f"[yellow]`{what}` is not built yet ({stage}).[/yellow]")
    raise typer.Exit(ExitCode.ERROR)


def parse_severity_option(value: str | None) -> set[Severity] | None:
    if value is None:
        return None
    wanted: set[Severity] = set()
    for part in value.split(","):
        name = part.strip().upper()
        if not name:
            continue
        try:
            wanted.add(Severity(name))
        except ValueError:
            choices = ", ".join(s.value for s in Severity)
            _fail(f"unknown severity '{part.strip()}'; use: {choices}")
    return wanted or None


@app.command("scan")
def scan_cmd(
    path: PathArg = Path(),
    imports: ImportOpt = None,
    severity: SeverityOpt = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write a JSON report.")] = None,
    sarif_out: Annotated[Path | None, typer.Option("--sarif", help="Write a SARIF report.")] = None,
) -> None:
    """Collect, merge and prioritize findings. Changes nothing."""
    cfg = _load_config_or_exit(path)
    if imports or cfg.imports:
        _not_yet("--import / imports:", "Stage 5")
    if sarif_out is not None:
        _not_yet("--sarif", "Stage 5")
    only = parse_severity_option(severity)
    try:
        result = run_scan(path, cfg, only)
    except (DetectError, SourceError) as exc:
        _fail(str(exc))
    render_scan(result, console)
    if json_out is not None:
        write_scan_json(result, json_out)
        console.print(f"JSON report: {json_out}")
    if result.shown:
        raise typer.Exit(ExitCode.FINDINGS_REMAIN)


@app.command("fix")
def fix_cmd(
    path: PathArg = Path(),
    imports: ImportOpt = None,
    severity: SeverityOpt = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show planned upgrades; change nothing.")
    ] = False,
    no_push: Annotated[
        bool,
        typer.Option("--no-push", help="Commit locally and write the PR body to a file only."),
    ] = False,
    keep_worktree: Annotated[
        bool, typer.Option("--keep-worktree", help="Keep the temporary worktree for inspection.")
    ] = False,
) -> None:
    """Full loop in a temporary worktree, then open or update the one PR."""
    cfg = _load_config_or_exit(path)
    if imports or cfg.imports:
        _not_yet("--import / imports:", "Stage 5")
    only = parse_severity_option(severity)
    try:
        outcome = run_fix(path, cfg, only, dry_run=dry_run, keep_worktree=keep_worktree)
    except (DetectError, SourceError, WorktreeError, FixError, LockError) as exc:
        _fail(str(exc))
    render_fix(outcome, console)
    raise typer.Exit(outcome.exit_code)
