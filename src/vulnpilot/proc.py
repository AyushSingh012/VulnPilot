"""The one place VulnPilot runs external tools.

Commands are always argv lists (never ``shell=True``), so nothing from a repo or a
scanner file is ever interpreted by a shell.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


class ToolNotFoundError(Exception):
    """The executable is not on PATH."""

    def __init__(self, tool: str) -> None:
        super().__init__(f"'{tool}' was not found on PATH")
        self.tool = tool


class ToolTimeoutError(Exception):
    """The command ran longer than its timeout."""

    def __init__(self, cmd: Sequence[str], timeout: float) -> None:
        super().__init__(f"'{' '.join(cmd)}' timed out after {timeout:g}s")
        self.cmd = list(cmd)
        self.timeout = timeout


@dataclass(frozen=True)
class ProcResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


Runner = Callable[[Sequence[str]], ProcResult]
"""Signature used wherever a command runner can be swapped out in tests."""


def run(
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> ProcResult:
    """Run ``cmd`` and capture its output. Never raises on a non-zero exit code."""
    try:
        completed = subprocess.run(
            list(cmd),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(env) if env is not None else None,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(cmd[0]) from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(cmd, timeout or 0) from exc
    return ProcResult(completed.returncode, completed.stdout, completed.stderr)
