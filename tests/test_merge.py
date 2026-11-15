from vulnpilot.models import Finding, Severity, SourceHit, finding_key
from vulnpilot.sources.merge import merge_findings


def f(
    aliases: list[str],
    *,
    source: str = "osv",
    sev: Severity = Severity.MEDIUM,
    cvss: float | None = None,
    fixed: list[str] | None = None,
    version: str = "1.0.0",
) -> Finding:
    return Finding(
        key=finding_key("PyPI", "demo", aliases),
        advisory_id=aliases[0],
        aliases=aliases,
        ecosystem="PyPI",
        package="demo",
        installed_version=version,
        fixed_versions=fixed or [],
        severity=sev,
        cvss=cvss,
        sources=[
            SourceHit(source=source, tool=source, raw_id=aliases[0], installed_version=version)
        ],
    )


def test_transitive_alias_overlap_merges_into_one() -> None:
    merged = merge_findings(
        [
            f(["GHSA-1", "PYSEC-1"], source="osv", fixed=["1.2.0"]),
            f(["CVE-1", "GHSA-1"], source="import:trivy.json", sev=Severity.HIGH, cvss=7.5),
            f(["CVE-1"], source="import:wiz.json", fixed=["1.1.0"]),
        ]
    )
    assert len(merged) == 1
    one = merged[0]
    assert one.aliases == ["CVE-1", "GHSA-1", "PYSEC-1"]
    assert one.advisory_id == "CVE-1"
    assert one.severity is Severity.HIGH
    assert one.cvss == 7.5
    assert one.fixed_versions == ["1.1.0", "1.2.0"]
    assert [s.source for s in one.sources] == ["osv", "import:trivy.json", "import:wiz.json"]
    assert one.key == "PyPI|demo|CVE-1"


def test_unrelated_advisories_stay_separate() -> None:
    assert len(merge_findings([f(["CVE-1"]), f(["CVE-2"])])) == 2


def test_different_installed_versions_stay_separate() -> None:
    assert len(merge_findings([f(["CVE-1"], version="1.0.0"), f(["CVE-1"], version="2.0.0")])) == 2
