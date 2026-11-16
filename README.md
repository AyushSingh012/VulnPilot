# VulnPilot

Finds vulnerable dependencies in a Python project (uv or Poetry), upgrades them to the
lowest safe version, runs your tests, rescans to confirm each fix, and opens **one** GitHub
pull request with everything that is confirmed. Nothing counts as fixed without a clean
rescan, and nothing counts as tested without passing tests.

## Install

You need Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```sh
uv tool install "git+https://github.com/AyushSingh012/VulnPilot@v0.1.2"
vulnpilot --version
```

VulnPilot drives these tools; install any that are missing:

| Tool | Needed for | Install |
|---|---|---|
| `osv-scanner` v2 | finding vulnerabilities | `brew install osv-scanner` or the [releases page](https://github.com/google/osv-scanner/releases) |
| `uv` | uv projects | already installed above |
| `poetry` | Poetry projects only | [python-poetry.org](https://python-poetry.org/docs/#installation) |
| `git` | `fix` | `brew install git` |
| `gh` (logged in) | opening the PR | `brew install gh`, then `gh auth login` |

Then check everything at once:

```sh
vulnpilot doctor
```

## First run

Run these from the project folder (the one with `pyproject.toml` and `uv.lock` or `poetry.lock`).

```sh
vulnpilot scan                 # what is vulnerable; changes nothing
vulnpilot fix --dry-run        # which upgrades it would make; changes nothing
vulnpilot fix --no-push        # the whole loop, committed to a local branch only
vulnpilot fix                  # the whole loop, then opens or updates the PR
```

`--no-push` is the safe way to try it: it commits to the local branch
`vulnpilot/security-fixes`, writes the PR text to a file in the run folder, and pushes
nothing. Look at the result with `git log -p vulnpilot/security-fixes`.

### What `fix` does

1. Makes a temporary copy (git worktree) of `origin/main`, so your checkout is never touched.
2. Scans the lockfile and picks, for each vulnerable package, the lowest release that fixes it.
3. Runs your tests once before changing anything, and stops if they already fail.
4. Upgrades the packages (only `pyproject.toml` and the lockfile change), runs the tests, and
   if they fail, finds the upgrade that breaks them and leaves just that one out.
5. Rescans; only what the rescan no longer finds counts as fixed.
6. Commits to `vulnpilot/security-fixes`, rebuilt from the base branch on every run, and
   opens the PR, or updates the one already open. There is never more than one.

The PR lists every finding: fixed, fixed but not tested, and not fixed with the reason
(breaks tests, needs a major upgrade, no fix released, …). Failing tests are named, never
copied in. VulnPilot opens no PR if an upgrade brings in a new vulnerability, and never
overwrites the branch if someone else has committed to it.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at or above the threshold remains |
| 1 | Findings remain (listed with the reason), or an upgrade brought in a new one |
| 2 | Something stopped the run; the message ends with a `Fix:` line saying what to do |

## Which vulnerabilities get fixed

By default **HIGH and CRITICAL**, plus:

- findings with no severity rating (they count as HIGH until a source rates them);
- findings on CISA's Known Exploited (KEV) list, or with an EPSS score of 0.1 or more, at
  any severity;
- lower-severity advisories on a package that is being upgraded anyway, when a release in
  the same major version fixes them too.

Everything else is listed in the PR under "Skipped". To include more:

```sh
vulnpilot fix --min-severity MEDIUM      # this run only; LOW includes everything
vulnpilot fix --severity MEDIUM,HIGH     # an exact set
```

or set `severity_threshold` in `vulnpilot.yml` (below).

## Trivy and Wiz reports

If you also scan with Trivy or Wiz (for example the container image in CI), pass their JSON
reports and VulnPilot merges them with its own scan. The same CVE from several tools shows
once, with every source listed.

```sh
trivy image --scanners vuln --format json -o trivy.json <image>
wizcli scan container-image <image> --by-policy-hits DISABLED --json-output-file wiz.json
vulnpilot fix --import trivy.json --import wiz.json
```

Each finding is matched to the lockfile:

| Finding | Result |
|---|---|
| Package in the lockfile, at an affected version | Fixed like any other finding |
| Package in the lockfile, already fixed there (the image was built earlier) | FIXED_IN_SOURCE: rebuild the image |
| OS package, or a package the lockfile doesn't have | OUT_OF_SCOPE: needs a base-image or Dockerfile change |

A project needs no Dockerfile: the lockfile scan covers every Python package it uses.
Secret findings in an imported report are never read, printed or stored.

## Configuration: `vulnpilot.yml`

Optional, in the project folder. Every key is optional; unknown keys are an error.

```yaml
severity_threshold: HIGH        # LOW | MEDIUM | HIGH | CRITICAL
allow_major_upgrades: false     # true lets a fix move to a new major version
imports: []                     # Trivy / Wiz JSON files, relative to the project
osv_offline: true               # match against a local OSV database (see below)
enrich: true                    # look up KEV and EPSS for each CVE

validate:
  install: null                 # default: uv sync --frozen / poetry sync
  test: null                    # default: uv run pytest -q / poetry run pytest -q; "none" = no tests
  timeout_minutes: 15
  retries: 1                    # re-run failing tests before blaming an upgrade
  isolate_breakers: true        # find and drop only the upgrade that breaks tests

ignore:                         # hide a finding until a date, with a reason
  - id: CVE-2024-12345
    reason: not reachable; tracked in SEC-42
    expires: 2026-12-31

pr:
  base_branch: main
  branch: vulnpilot/security-fixes
  labels: [security, dependencies]   # labels missing from the repo are skipped with a warning
  reviewers: []
  gh_user: null                 # open the PR as this gh account (must be logged in)
  repo: null                    # owner/name; default: read from the origin remote
```

`gh_user` lets you keep your usual account active in `gh`: VulnPilot uses that account's
token for its own `gh` and `git push` calls only.

## What leaves your machine

| Where | What is sent | When |
|---|---|---|
| osv-vulnerabilities.storage.googleapis.com | nothing about the project: the PyPI vulnerability database (about 36 MB) is downloaded and matched locally | every scan (`osv_offline: true`) |
| api.osv.dev | the name and version of every package in the lockfile | only with `osv_offline: false` |
| PyPI | names of the packages being upgraded, to list their releases | `fix` |
| CISA | nothing (the KEV catalog is downloaded, at most daily) | `enrich: true` |
| FIRST (EPSS) | CVE IDs | `enrich: true` |
| GitHub | the branch and the PR | `fix` without `--no-push` |

Run data (raw scanner output, test logs, the report) stays in
`~/.cache/vulnpilot/runs/<run-id>/`.

## Poetry projects

Poetry projects get the same exact versions as uv projects, not the newest version the
range allows: each target is pinned in a temporary dependency group, locked, then unpinned
and locked again, and Poetry keeps the locked versions. A constraint that blocks a fix gets
the smallest edit in Poetry's own style (`"2.31.0"` → `"2.33.0"`, `^2.31` → `^3.0.1`).
Poetry 1.x and 2.x both work.

Poetry rejects any version that declares `python <4` when the project's range is open-ended
(`>=3.12`), so bound it (`>=3.12,<4` or `^3.12`), as most Poetry projects already do.

## Output files

`scan` and `fix` take `--json FILE` and `--sarif FILE`. The SARIF file (2.1.0) points each
finding at the package's line in the lockfile, for GitHub code scanning; after `fix` it lists
only what is still open.

## Limits in v1

- Single-project repos; uv workspaces are not supported.
- PyPI packages only; OS packages in images are reported, not fixed.
- GitHub only, run by hand on your machine.

## Development

```sh
uv sync            # install
make check         # ruff + mypy (strict) + offline tests
make integration   # live scan + fix on every fixture (uv, Poetry, osv-scanner, PyPI, pytest)
make github-test   # real PRs on a throwaway repo; see tests/test_github_live.py
make osv-data      # refresh saved osv-scanner output used by the offline tests
make fixtures      # regenerate fixture lockfiles at their seeded vulnerable versions
scripts/capture_imports.sh   # rebuild the sample Trivy / Wiz files in tests/data/imports
uv run python scripts/fixture_repo.py tests-break /tmp/tb   # a fixture as its own git repo
```

`tests/fixtures/{uv,poetry}/<name>/` are small projects pinned to known-vulnerable versions.
Each has a `fixture.yaml` with its seed versions and the expected `scan` and `fix` results,
which the integration tests check.
