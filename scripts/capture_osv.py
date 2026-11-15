"""Save real osv-scanner output for each fixture, for offline unit tests.

Usage:  uv run python scripts/capture_osv.py

Writes tests/data/osv/<fixture>.json. The absolute lockfile path is replaced with a
path relative to the repo, so no local directory names end up in the repository.
Re-run when fixtures change or to pick up newly published advisories.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
OUT = REPO / "tests" / "data" / "osv"


def capture(fixture_dir: Path) -> None:
    lock = fixture_dir / "uv.lock"
    result = subprocess.run(
        ["osv-scanner", "scan", "source", "-L", str(lock), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise SystemExit(f"osv-scanner failed on {fixture_dir.name}: {result.stderr[-500:]}")
    data = json.loads(result.stdout)
    for res in data.get("results", []):
        res["source"]["path"] = str(lock.relative_to(REPO))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{fixture_dir.name}.json").write_text(json.dumps(data, indent=1) + "\n", "utf-8")
    print(f"ok   {fixture_dir.name}")


def main() -> int:
    for spec in sorted(FIXTURES.glob("uv/*/fixture.yaml")):
        capture(spec.parent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
