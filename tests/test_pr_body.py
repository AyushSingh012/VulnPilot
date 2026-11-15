from datetime import UTC, datetime

from vulnpilot.models import (
    Finding,
    FixResult,
    FixStatus,
    RunReport,
    Severity,
    Upgrade,
    UpgradeMethod,
    ValidationResult,
    finding_key,
)
from vulnpilot.pr_body import GITHUB_LIMIT, MARKER, BodyInput, body, render, title


def f(pkg: str, cve: str, sev: Severity = Severity.HIGH, version: str = "1.0") -> Finding:
    return Finding(
        key=finding_key("PyPI", pkg, [cve]),
        advisory_id=cve,
        aliases=[cve],
        ecosystem="PyPI",
        package=pkg,
        installed_version=version,
        severity=sev,
    )


def up(
    pkg: str, to: str, method: UpgradeMethod = "lock-upgrade", parents: list[str] | None = None
) -> Upgrade:
    return Upgrade(
        package=pkg,
        from_version="1.0",
        to_version=to,
        method=method,
        finding_keys=[],
        parents=parents or [],
    )


def report(results: list[tuple[Finding, FixStatus, Upgrade | None, str]]) -> RunReport:
    return RunReport(
        run_id="20261115-000000-abcd",
        repo="demo",
        commit_sha="0123456789abcdef",
        started_at=datetime(2026, 11, 15, tzinfo=UTC),
        tool_versions={"osv-scanner": "2.7.1"},
        findings_before=[r[0] for r in results],
        results=[
            FixResult(finding_key=fi.key, status=s, upgrade=u, note=n) for fi, s, u, n in results
        ],
        baseline=ValidationResult(ran=True, passed=True),
        final=ValidationResult(ran=True, passed=True),
    )


REQ = up("requests", "2.33.0", "raise-bound")
RPT = report(
    [
        (f("requests", "CVE-2024-1"), FixStatus.FIXED_AND_VALIDATED, REQ, ""),
        (f("requests", "CVE-2024-2", Severity.MEDIUM), FixStatus.FIXED_AND_VALIDATED, REQ, ""),
        (
            f("urllib3", "CVE-2024-3"),
            FixStatus.FIXED_AND_VALIDATED,
            up("urllib3", "2.8.0", "parent-upgrade", ["botocore"]),
            "upgraded together with botocore",
        ),
        (
            f("jinja2", "CVE-2024-4"),
            FixStatus.FIXED_BUT_TESTS_FAILED,
            up("jinja2", "3.1.6"),
            "breaks tests: tests/test_x.py::test_a",
        ),
        (
            f("idna", "CVE-2024-5"),
            FixStatus.NO_SAFE_FIX,
            None,
            "needs a major upgrade (fixed in 4.0)",
        ),
        (f("six", "CVE-2024-6", Severity.LOW), FixStatus.SKIPPED, None, "below severity threshold"),
        (f("pip", "CVE-2024-7"), FixStatus.STILL_PRESENT, None, "a | pipe in the note"),
    ]
)
CHANGES = {"requests": [("requests==1.0", "requests==2.33.0")]}


def test_title_counts_fixed_and_names_packages() -> None:
    assert title(RPT) == "VulnPilot: fix 3 vulnerabilities (requests, urllib3)"


def test_body_lists_every_finding_in_its_section() -> None:
    text = body(BodyInput(RPT, "origin/main", CHANGES))
    assert text.startswith(MARKER)
    assert "**3 vulnerabilities** in 2 packages" in text
    assert "## Fixed" in text and "tests passed before the change and with it" in text
    assert "rescan with OSV-Scanner confirms" in text
    assert "| `requests` | 1.0 → 2.33.0 |" in text
    assert "pyproject.toml: `requests==1.0` → `requests==2.33.0`" in text
    assert "[CVE-2024-1](https://osv.dev/vulnerability/CVE-2024-1) (high)" in text
    assert "upgraded with botocore" in text
    assert "### Needs code changes (1)" in text
    assert "upgrading to 3.1.6 breaks tests: tests/test_x.py::test_a" in text
    assert "### No safe fix (1)" in text and "needs a major upgrade" in text
    assert "### Still present (1)" in text and "a \\| pipe in the note" in text
    assert "<summary>Skipped (1)</summary>" in text
    assert "base `origin/main` @ `01234567`" in text
    assert "/Users/" not in text and "Not tested locally" not in text


def test_untested_fixes_get_their_own_heading() -> None:
    rpt = report([(f("a", "CVE-1"), FixStatus.FIXED_NOT_TESTED, up("a", "2.0"), "")])
    rpt.final = None
    text = body(BodyInput(rpt, "origin/main"))
    assert "## Not tested locally — check CI" in text and "## Fixed" not in text
    assert "## Not fixed" not in text


def test_huge_body_is_shortened_under_the_limit() -> None:
    many = [
        (f(f"pkg{i}", f"CVE-2024-{i:05d}"), FixStatus.NO_SAFE_FIX, None, "x" * 300)
        for i in range(400)
    ]
    rpt = report([(f("a", "CVE-1"), FixStatus.FIXED_AND_VALIDATED, up("a", "2.0"), ""), *many])
    _, text = render(BodyInput(rpt, "origin/main"))
    assert len(text) <= GITHUB_LIMIT
    assert "more (see report.json from this run)" in text


def test_not_fixed_rows_are_grouped_per_package() -> None:
    upgrade = up("jinja2", "3.1.6")
    note = "breaks tests: t::a"
    rpt = report(
        [
            (f("jinja2", f"CVE-2024-{i}"), FixStatus.FIXED_BUT_TESTS_FAILED, upgrade, note)
            for i in range(5)
        ]
    )
    text = body(BodyInput(rpt, "origin/main"))
    rows = [line for line in text.splitlines() if line.startswith("| `jinja2`")]
    assert len(rows) == 1 and rows[0].count("osv.dev") == 5
