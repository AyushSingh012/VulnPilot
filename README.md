# VulnPilot

Scan a Python project (uv first, then Poetry) for vulnerable dependencies, upgrade them,
run the tests, rescan, and open one GitHub PR with every fix that is confirmed.

Status: v1 in progress. `doctor` and `scan` work; `fix` is being built.

```sh
vulnpilot doctor                      # check external tools
vulnpilot scan [PATH]                 # findings table; exit 1 if any remain
vulnpilot scan . --severity HIGH,CRITICAL --json report.json
```

`scan` changes nothing in the project. Raw scanner output is kept under
`~/.cache/vulnpilot/runs/<run-id>/`.

## Development

```sh
uv sync            # install
make check         # ruff + mypy (strict) + pytest (offline)
make integration   # live osv-scanner against the fixtures
make osv-data      # refresh saved osv-scanner output used by offline tests
make fixtures      # regenerate fixture lockfiles at their seeded vulnerable versions
uv run vulnpilot doctor
```

External tools VulnPilot drives: `osv-scanner` (v2), `uv`, `git`, `gh`, and `poetry` for
Poetry projects. `vulnpilot doctor` checks them.

## Fixtures

`tests/fixtures/uv/<name>/` are small uv projects pinned to known-vulnerable versions.
Each has a `fixture.yaml` describing its seed versions and the expected `scan` findings
and `fix` results; the integration tests in later stages run VulnPilot against them.
