"""Regenerate every fixture lockfile at its seeded (vulnerable) versions.

Usage:  uv run python scripts/regen_fixtures.py [fixture-name ...]

Each fixture directory has a ``fixture.yaml`` whose ``seed`` maps package -> version.
The lockfile is resolved normally, then each seeded package is moved to its seed
version: ``uv lock --upgrade-package <pkg>==<version>`` for uv; for Poetry, a temporary
pin group, ``poetry lock``, then the group removed and ``poetry lock`` again (Poetry keeps
locked versions). Either way the seed sticks because it still satisfies pyproject.toml.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

from vulnpilot.fixers.poetry_fix import with_pins

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def regen_poetry(fixture_dir: Path, seed: dict[str, str]) -> None:
    env = {**os.environ, "POETRY_NO_INTERACTION": "1"}
    (fixture_dir / "poetry.lock").unlink(missing_ok=True)
    pyproject = fixture_dir / "pyproject.toml"
    original = pyproject.read_text(encoding="utf-8")
    try:
        if seed:
            pyproject.write_text(with_pins(original, seed), encoding="utf-8")
            subprocess.run(["poetry", "lock", "-q"], cwd=fixture_dir, check=True, env=env)
            pyproject.write_text(original, encoding="utf-8")
        subprocess.run(["poetry", "lock", "-q"], cwd=fixture_dir, check=True, env=env)
    finally:
        pyproject.write_text(original, encoding="utf-8")


def regen(fixture_dir: Path) -> None:
    spec = yaml.safe_load((fixture_dir / "fixture.yaml").read_text(encoding="utf-8"))
    if spec["manager"] == "poetry":
        regen_poetry(fixture_dir, spec.get("seed") or {})
        print(f"ok   {fixture_dir.relative_to(FIXTURES)}")
        return
    lock = fixture_dir / "uv.lock"
    lock.unlink(missing_ok=True)
    subprocess.run(["uv", "lock", "-q"], cwd=fixture_dir, check=True)
    seed: dict[str, str] = spec.get("seed") or {}
    if seed:
        args = ["uv", "lock", "-q"]
        for pkg, ver in seed.items():
            args += ["--upgrade-package", f"{pkg}=={ver}"]
        subprocess.run(args, cwd=fixture_dir, check=True)
    print(f"ok   {fixture_dir.relative_to(FIXTURES)}")


def main(names: list[str]) -> int:
    dirs = sorted(p.parent for p in FIXTURES.glob("*/*/fixture.yaml"))
    if names:
        dirs = [d for d in dirs if d.name in names]
    for d in dirs:
        regen(d)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
