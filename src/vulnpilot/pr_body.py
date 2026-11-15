"""Title and Markdown body of the VulnPilot PR.

Every finding appears somewhere: fixed, fixed but untested, or not fixed with the reason.
Failing tests are listed by name only (test output can hold secrets), and no local paths
from the developer's machine are included.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from vulnpilot import __version__
from vulnpilot.models import Finding, FixResult, FixStatus, RunReport, Severity

MARKER = "<!-- vulnpilot:pr -->"
GITHUB_LIMIT = 60_000  # GitHub allows 65,536 characters; keep a margin
_OSV = "https://osv.dev/vulnerability/"


@dataclass
class BodyInput:
    report: RunReport
    base_ref: str
    pyproject_changes: dict[str, list[tuple[str, str]]] = field(default_factory=dict)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _advisory(f: Finding) -> str:
    sev = "" if f.severity is Severity.UNKNOWN else f" ({f.severity.value.lower()})"
    kev = " **KEV**" if f.in_kev else ""
    epss = f" EPSS {f.epss:.0%}" if f.epss is not None and f.epss >= 0.1 else ""
    return f"[{f.advisory_id}]({_OSV}{f.advisory_id}){sev}{kev}{epss}"


def _how(r: FixResult, changes: dict[str, list[tuple[str, str]]]) -> str:
    u = r.upgrade
    if u is None:
        return ""
    if u.method == "raise-bound" and changes.get(u.package):
        return "; ".join(f"pyproject.toml: `{old}` → `{new}`" for old, new in changes[u.package])
    if u.method == "parent-upgrade":
        return f"upgraded with {', '.join(u.parents)}"
    return "lockfile only"


def _table(header: list[str], rows: list[list[str]], max_rows: int | None) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    shown = rows if max_rows is None else rows[:max_rows]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in shown]
    if len(shown) < len(rows):
        lines.append(f"\n…and {len(rows) - len(shown)} more (see report.json from this run).")
    return lines


def _by_package(results: list[FixResult], by_key: dict[str, Finding]) -> dict[str, list[FixResult]]:
    grouped: dict[str, list[FixResult]] = defaultdict(list)
    for r in results:
        grouped[by_key[r.finding_key].package.lower()].append(r)
    return dict(sorted(grouped.items()))


def _fixed_rows(
    results: list[FixResult], by_key: dict[str, Finding], changes: dict[str, list[tuple[str, str]]]
) -> list[list[str]]:
    rows = []
    for pkg, items in _by_package(results, by_key).items():
        u = items[0].upgrade
        change = f"{u.from_version} → {u.to_version}" if u else ""
        advisories = ", ".join(_advisory(by_key[r.finding_key]) for r in items)
        rows.append([f"`{pkg}`", change, advisories, _how(items[0], changes)])
    return rows


def _reason(r: FixResult) -> str:
    if r.status is FixStatus.FIXED_BUT_TESTS_FAILED and r.upgrade is not None:
        return f"upgrading to {r.upgrade.to_version} {r.note}"
    return r.note


def _reason_rows(results: list[FixResult], by_key: dict[str, Finding]) -> list[list[str]]:
    """One row per package and reason, with all its advisories in that row."""
    grouped: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for r in results:
        f = by_key[r.finding_key]
        grouped[(f.package.lower(), f.installed_version, _reason(r))].append(f)
    return [
        [f"`{pkg}` {version}", ", ".join(_advisory(f) for f in findings), why]
        for (pkg, version, why), findings in sorted(grouped.items())
    ]


def title(report: RunReport) -> str:
    by_key = {f.key: f for f in report.findings_before}
    fixed = [r for r in report.results if r.status.counts_as_fixed]
    pkgs = sorted({by_key[r.finding_key].package.lower() for r in fixed})
    names = ", ".join(pkgs[:3]) + (f", +{len(pkgs) - 3} more" if len(pkgs) > 3 else "")
    return f"VulnPilot: fix {_plural(len(fixed), 'vulnerability', 'vulnerabilities')} ({names})"


def body(data: BodyInput, *, max_rows: int | None = None, with_skipped: bool = True) -> str:
    report = data.report
    by_key = {f.key: f for f in [*report.findings_after, *report.findings_before]}
    groups: dict[FixStatus, list[FixResult]] = defaultdict(list)
    for r in report.results:
        groups[r.status].append(r)
    validated = groups[FixStatus.FIXED_AND_VALIDATED]
    untested = groups[FixStatus.FIXED_NOT_TESTED]
    fixed_total = len(validated) + len(untested)
    not_fixed_statuses = (
        FixStatus.FIXED_BUT_TESTS_FAILED,
        FixStatus.STILL_PRESENT,
        FixStatus.NO_SAFE_FIX,
        FixStatus.FIXED_IN_SOURCE,
        FixStatus.OUT_OF_SCOPE,
    )
    not_fixed = sum(len(groups[s]) for s in not_fixed_statuses)
    pkgs = {by_key[r.finding_key].package.lower() for r in [*validated, *untested]}

    out = [
        MARKER,
        f"This PR fixes **{_plural(fixed_total, 'vulnerability', 'vulnerabilities')}** in "
        f"{_plural(len(pkgs), 'package')}. It changes only `pyproject.toml` and the lockfile.",
    ]
    if not_fixed:
        out.append(
            f"{_plural(not_fixed, 'other finding')} could not be fixed here; each is listed "
            "below with the reason."
        )

    fixed_header = ["Package", "Change", "Advisories", "How"]
    if validated:
        out += ["", "## Fixed", ""]
        tested = report.final is not None and report.final.ran and report.final.passed
        out += [
            ("The project's tests passed before the change and with it. " if tested else "")
            + "A rescan with OSV-Scanner confirms each of these is gone.",
            "",
        ]
        out += _table(
            fixed_header, _fixed_rows(validated, by_key, data.pyproject_changes), max_rows
        )
    if untested:
        out += [
            "",
            "## Not tested locally — check CI",
            "",
            "Tests are turned off for this repo (`validate.test: none`), so these upgrades "
            "were not run against the test suite. A rescan confirms each one is gone.",
            "",
        ]
        out += _table(fixed_header, _fixed_rows(untested, by_key, data.pyproject_changes), max_rows)

    sections = [
        (FixStatus.FIXED_BUT_TESTS_FAILED, "Needs code changes",
         "The upgrade removes the vulnerability but makes these tests fail, so it is left out."),
        (FixStatus.STILL_PRESENT, "Still present",
         "An upgrade was tried but the vulnerability is still there."),
        (FixStatus.NO_SAFE_FIX, "No safe fix", "No fixed release fits, or only a major upgrade."),
        (FixStatus.FIXED_IN_SOURCE, "Rebuild the image",
         "The lockfile already has a fixed version; the image was built before it."),
        (FixStatus.OUT_OF_SCOPE, "Needs a base-image or Dockerfile change",
         "Found in an image, but not managed by the lockfile."),
    ]  # fmt: skip
    if not_fixed:
        out += ["", "## Not fixed"]
    for status, heading, intro in sections:
        if groups[status]:
            out += ["", f"### {heading} ({len(groups[status])})", "", intro, ""]
            rows = _reason_rows(groups[status], by_key)
            out += _table(["Package", "Advisories", "Why"], rows, max_rows)

    skipped = groups[FixStatus.SKIPPED]
    if skipped and with_skipped:
        out += ["", f"<details><summary>Skipped ({len(skipped)})</summary>", ""]
        out += _table(["Package", "Advisories", "Why"], _reason_rows(skipped, by_key), max_rows)
        out += ["", "</details>"]

    tools = ", ".join(f"{k} {v}" for k, v in sorted(report.tool_versions.items()))
    sha = (report.commit_sha or "")[:8]
    out += [
        "",
        "---",
        f"<sub>VulnPilot {__version__} · run `{report.run_id}` · base `{data.base_ref}` @ "
        f"`{sha}`{' · ' + tools if tools else ''}. This branch is rebuilt on every run; "
        "push your own changes to a different branch.</sub>",
    ]
    return "\n".join(out) + "\n"


def render(data: BodyInput) -> tuple[str, str]:
    """(title, body), shortened if the body would pass GitHub's size limit."""
    text = body(data)
    if len(text) > GITHUB_LIMIT:
        text = body(data, max_rows=50, with_skipped=False)
    if len(text) > GITHUB_LIMIT:
        text = body(data, max_rows=10, with_skipped=False)
    return title(data.report), text
