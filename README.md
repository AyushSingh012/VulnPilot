# VulnPilot

Scan a Python project (uv first, then Poetry) for vulnerable dependencies, upgrade them,
run the tests, rescan, and open one GitHub PR with every fix that is confirmed.

Status: v1 in progress. `doctor`, `scan` and the `fix` loop work; commit / push / PR come next.

```sh
vulnpilot doctor                      # check external tools
vulnpilot scan [PATH]                 # findings table; exit 1 if any remain
vulnpilot scan . --severity HIGH,CRITICAL --json report.json
vulnpilot fix [PATH] --dry-run        # planned upgrades; nothing tested or changed
vulnpilot fix [PATH]                  # upgrade, test, isolate breakers, rescan, report
```

`fix` works in a temporary git worktree of `origin/<base_branch>` (or the local base
branch when there is no `origin`), so your checkout is never touched. It runs your tests
once before any change and stops if they already fail. Upgrades that break tests are found
by bisection and left out; everything else is rescanned before it counts as fixed.

`scan` changes nothing in the project. Raw scanner output is kept under
`~/.cache/vulnpilot/runs/<run-id>/`.

## Development

```sh
uv sync            # install
make check         # ruff + mypy (strict) + pytest (offline)
make integration   # live scan + fix against every fixture (uv, osv-scanner, PyPI, pytest)
make osv-data      # refresh saved osv-scanner output used by offline tests
make fixtures      # regenerate fixture lockfiles at their seeded vulnerable versions
uv run python scripts/fixture_repo.py tests-break /tmp/tb   # a fixture as its own git repo
uv run vulnpilot doctor
```

External tools VulnPilot drives: `osv-scanner` (v2), `uv`, `git`, `gh`, and `poetry` for
Poetry projects. `vulnpilot doctor` checks them.

## Fixtures

`tests/fixtures/uv/<name>/` are small uv projects pinned to known-vulnerable versions.
Each has a `fixture.yaml` describing its seed versions and the expected `scan` findings
and `fix` results; the integration tests in later stages run VulnPilot against them.
