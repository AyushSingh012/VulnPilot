"""Install the project and run its tests (commands come only from local config)."""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

from vulnpilot import proc
from vulnpilot.config import ValidateConfig
from vulnpilot.fixers.poetry_fix import poetry_major
from vulnpilot.models import Manager, ValidationResult
from vulnpilot.proc import ToolNotFoundError, ToolTimeoutError

_FAILED_RE = re.compile(r"^(?:FAILED|ERROR) (\S+)", re.MULTILINE)
MAX_FAILED_NAMES = 20


def tool_env(run_dir: Path) -> dict[str, str]:
    """Environment for uv / Poetry / test runs: keep venvs and bytecode out of the worktree."""
    env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}
    env["UV_PROJECT_ENVIRONMENT"] = str(run_dir / "venv")
    env["POETRY_VIRTUALENVS_PATH"] = str(run_dir / "poetry-venvs")
    env["POETRY_VIRTUALENVS_IN_PROJECT"] = "false"
    env["POETRY_VIRTUALENVS_CREATE"] = "true"
    env["POETRY_NO_INTERACTION"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def install_command(cfg: ValidateConfig, manager: Manager, env: dict[str, str]) -> str:
    """The configured install command, else the manager's default for its version."""
    if cfg.install or manager != "poetry":
        return cfg.install_command(manager)
    return "poetry sync" if poetry_major(env) >= 2 else "poetry install --sync"


def failed_test_names(output: str) -> list[str]:
    """Test IDs from pytest's short summary (`FAILED tests/x.py::test_y - ...`)."""
    names = list(dict.fromkeys(_FAILED_RE.findall(output)))
    return names[:MAX_FAILED_NAMES]


class Validator:
    def __init__(
        self,
        project_dir: Path,
        cfg: ValidateConfig,
        manager: Manager,
        env: dict[str, str],
        logs_dir: Path,
    ) -> None:
        self.project_dir = project_dir
        self.install_cmd = shlex.split(install_command(cfg, manager, env))
        test = cfg.test_command(manager)
        self.test_cmd = shlex.split(test) if test else None
        self.timeout = cfg.timeout_minutes * 60
        self.retries = cfg.retries
        self.env = env
        self.logs_dir = logs_dir

    @property
    def tests_enabled(self) -> bool:
        return self.test_cmd is not None

    def _exec(self, cmd: list[str], log: Path) -> tuple[bool, str]:
        with log.open("a", encoding="utf-8") as fh:
            fh.write(f"$ {shlex.join(cmd)}\n")
            try:
                result = proc.run(cmd, cwd=self.project_dir, timeout=self.timeout, env=self.env)
            except ToolNotFoundError:
                fh.write(f"{cmd[0]}: not found\n")
                return False, f"{cmd[0]}: not found"
            except ToolTimeoutError:
                fh.write(f"timed out after {self.timeout}s\n")
                return False, f"timed out after {self.timeout // 60} min"
            output = result.stdout + result.stderr
            fh.write(output + f"\n[exit {result.returncode}]\n\n")
        return result.ok, output

    def run(self, label: str) -> ValidationResult:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        log = self.logs_dir / f"{label}.log"
        log.unlink(missing_ok=True)
        ok, output = self._exec(self.install_cmd, log)
        if not ok:
            return ValidationResult(
                ran=self.tests_enabled,
                passed=False,
                failed_tests=["<install failed>"],
                log_path=str(log),
            )
        if self.test_cmd is None:
            return ValidationResult(ran=False, passed=True, log_path=str(log))
        failed: list[str] = []
        for _ in range(self.retries + 1):
            ok, output = self._exec(self.test_cmd, log)
            if ok:
                return ValidationResult(ran=True, passed=True, log_path=str(log))
            failed = failed_test_names(output) or ["<tests failed; see log>"]
        return ValidationResult(ran=True, passed=False, failed_tests=failed, log_path=str(log))
