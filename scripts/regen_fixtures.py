"""Regenerate every fixture lockfile at its seeded (vulnerable) versions.

Usage:  uv run python scripts/regen_fixtures.py [fixture-name ...]

Each fixture directory has a ``fixture.yaml`` whose ``seed`` maps package -> version.
The lockfile is resolved normally, then each seeded package is moved to its seed
version with ``uv lock --upgrade-package <pkg>==<version>`` (uv keeps it there on later
locks because the version still satisfies pyproject.toml).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def regen(fixture_dir: Path) -> None:
    spec = yaml.safe_load((fixture_dir / "fixture.yaml").read_text(encoding="utf-8"))
    if spec["manager"] != "uv":
        print(f"skip {fixture_dir.name}: manager {spec['manager']} not handled yet")
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
