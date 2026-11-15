# VulnPilot

Scan a Python project (uv first, then Poetry) for vulnerable dependencies, upgrade them,
run the tests, rescan, and open one GitHub PR with every fix that is confirmed.

Status: v1 in progress. `doctor`, `scan` and `fix` work end to end for uv projects
(Trivy / Wiz imports, KEV / EPSS and Poetry come next).

```sh
vulnpilot doctor                      # check external tools
vulnpilot scan [PATH]                 # findings table; exit 1 if any remain
vulnpilot scan . --severity HIGH,CRITICAL --json report.json
vulnpilot fix [PATH] --dry-run        # planned upgrades; nothing tested or changed
vulnpilot fix [PATH]                  # upgrade, test, isolate breakers, rescan, open/update the PR
vulnpilot fix [PATH] --no-push        # same, but commit to a local branch and write the PR body to a file
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
uv run python scripts/fixture_repo.py tests-break /tmp/tb   # a fixture as its own git repo
uv run vulnpilot doctor
```

External tools VulnPilot drives: `osv-scanner` (v2), `uv`, `git`, `gh`, and `poetry` for
Poetry projects. `vulnpilot doctor` checks them.

## Fixtures

`tests/fixtures/uv/<name>/` are small uv projects pinned to known-vulnerable versions.
Each has a `fixture.yaml` describing its seed versions and the expected `scan` findings
and `fix` results; the integration tests in later stages run VulnPilot against them.
