"""Command-line entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulnpilot import __version__, doctor
from vulnpilot.config import ConfigError, load_config
from vulnpilot.models import ExitCode

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


def _load_config_or_exit(path: Path) -> None:
    try:
        load_config(path)
    except ConfigError as exc:
        err_console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(ExitCode.ERROR) from exc


def _not_yet(what: str, stage: str) -> None:
    err_console.print(f"[yellow]`vulnpilot {what}` is not built yet ({stage}).[/yellow]")
    raise typer.Exit(ExitCode.ERROR)


@app.command("scan")
def scan_cmd(
    path: PathArg = Path(),
    imports: ImportOpt = None,
    severity: SeverityOpt = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write a JSON report.")] = None,
    sarif_out: Annotated[Path | None, typer.Option("--sarif", help="Write a SARIF report.")] = None,
) -> None:
    """Collect, merge and prioritize findings. Changes nothing."""
    _load_config_or_exit(path)
    _not_yet("scan", "Stage 2")


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
) -> None:
    """Full loop in a temporary worktree, then open or update the one PR."""
    _load_config_or_exit(path)
    _not_yet("fix", "Stages 3-4")
