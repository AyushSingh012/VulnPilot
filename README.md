# VulnPilot

Scan a Python project (uv first, then Poetry) for vulnerable dependencies, upgrade them,
run the tests, rescan, and open one GitHub PR with every fix that is confirmed.

Status: v1 in progress. `doctor`, `scan` and `fix` work end to end for uv projects, with
Trivy / Wiz imports, KEV / EPSS and SARIF. Poetry comes next.

```sh
vulnpilot doctor                      # check external tools
vulnpilot scan [PATH]                 # findings table; exit 1 if any remain
vulnpilot scan . --severity HIGH,CRITICAL --json report.json
vulnpilot fix [PATH] --dry-run        # planned upgrades; nothing tested or changed
vulnpilot fix [PATH]                  # upgrade, test, isolate breakers, rescan, open/update the PR
vulnpilot fix [PATH] --no-push        # same, but commit to a local branch and write the PR body to a file
vulnpilot scan . --import trivy.json --import wiz.json --sarif scan.sarif
```

`fix` works in a temporary git worktree of `origin/<base_branch>` (or the local base
branch when there is no `origin`), so your checkout is never touched. It runs your tests
once before any change and stops if they already fail. Upgrades that break tests are found
by bisection and left out; everything else is rescanned before it counts as fixed.

Fixes are committed (only `pyproject.toml` and the lockfile) to `vulnpilot/security-fixes`,
rebuilt from the base branch on every run and pushed with `--force-with-lease`. Every run
opens the PR or updates the open one, so there is never more than one. VulnPilot refuses to
overwrite that branch if it holds commits it didn't make, and opens no PR if an upgrade
brings in a new vulnerability (INTRODUCED, exit code 1).

To open PRs with a gh account other than the active one, set it in `vulnpilot.yml`;
its token is used for VulnPilot's own `gh` and `git push` calls only:

```yaml
pr:
  gh_user: your-github-login   # must be logged in: gh auth login
  labels: [security, dependencies]   # labels missing from the repo are skipped with a warning
```

### Trivy and Wiz files

`--import FILE` (repeatable) or `imports: [file, ...]` in `vulnpilot.yml` merges a Trivy or Wiz
JSON report, of the repo or of a container image, with OSV-Scanner's findings. The format is
detected from the file. Each finding is matched to the lockfile:

| Finding | Result |
|---|---|
| Package in the lockfile, at an affected version | Fixed like any other finding |
| Package in the lockfile, already at a fixed version (the image is older) | FIXED_IN_SOURCE: rebuild the image |
| OS package, or a Python package the lockfile does not have | OUT_OF_SCOPE: needs a base-image or Dockerfile change |

The same CVE from several tools is one finding listing every source. Secret findings in an
import are never read, printed or stored. Files made by Trivy 0.69.4–0.69.6 (compromised
releases) get a warning.

```sh
trivy image --scanners vuln --format json -o trivy.json <image>
wizcli scan container-image <image> --by-policy-hits DISABLED --json-output-file wiz.json
```

### Exploitation signals and order

Findings are marked from CISA's KEV catalog and FIRST's EPSS scores, then ordered: KEV first,
then EPSS ≥ 0.1, then severity, then EPSS. Only CVE IDs are sent to those services; answers
are cached for 24 hours under `~/.cache/vulnpilot/enrich/`. Offline, the last cached answer is
used with a warning. Set `enrich: false` in `vulnpilot.yml` to turn the lookups off.

### Output files

`scan` and `fix` take `--json FILE` and `--sarif FILE`. SARIF (2.1.0) points each finding at
the package's line in the lockfile, for GitHub code scanning; after `fix` it lists only what
is still open.

### Which vulnerabilities get fixed

By default HIGH and CRITICAL. Also included:

- findings with no severity rating (they count as HIGH until a source rates them);
- findings on CISA's KEV list, or with an EPSS score of 0.1 or more, at any severity;
- lower-severity advisories on a package that is being upgraded anyway, when a release in the
  same major fixes them too.

Everything else is listed in the PR under "Skipped". To include MEDIUM and LOW:

```yaml
severity_threshold: MEDIUM   # in vulnpilot.yml; LOW includes everything
```

or for one run: `vulnpilot fix --min-severity MEDIUM` (or an exact set: `--severity MEDIUM,HIGH`).

`scan` changes nothing in the project. Raw scanner output is kept under
`~/.cache/vulnpilot/runs/<run-id>/`.

## Development

```sh
uv sync            # install
make check         # ruff + mypy (strict) + pytest (offline)
make integration   # live scan + fix against every fixture (uv, osv-scanner, PyPI, pytest)
make github-test   # real PRs on a throwaway repo; see tests/test_github_live.py for the env vars
make osv-data      # refresh saved osv-scanner output used by offline tests
make fixtures      # regenerate fixture lockfiles at their seeded vulnerable versions
scripts/capture_imports.sh   # rebuild the sample Trivy / Wiz files in tests/data/imports
uv run python scripts/fixture_repo.py tests-break /tmp/tb   # a fixture as its own git repo
uv run vulnpilot doctor
```

External tools VulnPilot drives: `osv-scanner` (v2), `uv`, `git`, `gh`, and `poetry` for
Poetry projects. `vulnpilot doctor` checks them.

## Fixtures

`tests/fixtures/uv/<name>/` are small uv projects pinned to known-vulnerable versions.
Each has a `fixture.yaml` describing its seed versions and the expected `scan` findings
and `fix` results; the integration tests in later stages run VulnPilot against them.
