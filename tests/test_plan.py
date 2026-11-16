from pathlib import Path

from tests.conftest import FIXTURES, osv_data
from vulnpilot.detect import detect_project
from vulnpilot.lockgraph import load_graph
from vulnpilot.models import Finding, VersionRange, finding_key
from vulnpilot.plan import build_plan, candidates, choose_target, ride_along
from vulnpilot.pypi import StaticIndex, usable_releases
from vulnpilot.sources.merge import annotate, merge_findings
from vulnpilot.sources.osv import parse_osv_json
from vulnpilot.versions import bump_at, is_affected, is_major_upgrade


def adv(cve: str, *ranges: tuple[str, str | None]) -> Finding:
    return Finding(
        key=finding_key("PyPI", "demo", [cve]),
        advisory_id=cve,
        aliases=[cve],
        ecosystem="PyPI",
        package="demo",
        installed_version="1.4.0",
        fixed_versions=sorted(f for _, f in ranges if f),
        affected_ranges=[VersionRange(introduced=i, fixed=f) for i, f in ranges],
    )


A = adv("CVE-A", ("0", "1.4.2"))  # fixed in 1.4.2
B = adv("CVE-B", ("0", "1.5.0"))  # fixed in 1.5.0
C = adv("CVE-C", ("0", "2.1.0"))  # only fixed in 2.x
D = adv("CVE-D", ("0", None))  # never fixed
BRANCHY = adv("CVE-E", ("0", "1.4.3"), ("2.0.0", "2.0.5"))  # fixed on two lines
RELEASES = ["1.4.0", "1.4.1", "1.4.2", "1.4.3", "1.5.0", "1.5.1", "2.0.0", "2.0.5", "2.1.0"]


def test_lowest_version_fixing_all() -> None:
    target, fixed, reasons = choose_target("1.4.0", [A, B], RELEASES[1:], allow_major=False)
    assert target == "1.5.0"
    assert {f.advisory_id for f in fixed} == {"CVE-A", "CVE-B"}
    assert reasons == {}


def test_partial_fix_within_major() -> None:
    target, fixed, reasons = choose_target("1.4.0", [A, B, C], RELEASES[1:], allow_major=False)
    assert target == "1.5.0"
    assert {f.advisory_id for f in fixed} == {"CVE-A", "CVE-B"}
    assert "needs a major upgrade (fixed in 2.1.0)" in reasons[C.key]


def test_major_allowed_fixes_all() -> None:
    target, _, reasons = choose_target("1.4.0", [A, B, C], RELEASES[1:], allow_major=True)
    assert target == "2.1.0"
    assert reasons == {}


def test_never_fixed() -> None:
    target, fixed, reasons = choose_target("1.4.0", [D], RELEASES[1:], allow_major=True)
    assert target is None and fixed == []
    assert reasons[D.key] == "no fixed version has been released"


def test_branch_ranges_respected() -> None:
    assert not is_affected("1.4.3", BRANCHY)
    assert is_affected("2.0.0", BRANCHY)
    assert not is_affected("2.0.5", BRANCHY)
    target, _, _ = choose_target("1.4.0", [BRANCHY], RELEASES[1:], allow_major=True)
    assert target == "1.4.3"


def test_candidates_skip_yanked_and_prereleases() -> None:
    data = {
        "releases": {
            "1.4.0": [{"yanked": False}],
            "1.4.1": [{"yanked": True}],
            "1.4.2": [{"yanked": False}],
            "1.5.0rc1": [{"yanked": False}],
            "1.5.0": [],
        }
    }
    assert usable_releases(data) == ["1.4.0", "1.4.2"]
    index = StaticIndex({"demo": usable_releases(data)})
    assert candidates("demo", "1.4.0", [A], index) == (["1.4.2"], True)
    assert candidates("demo", "1.4.0", [A, B], StaticIndex()) == (["1.4.2", "1.5.0"], False)


def test_bump_at() -> None:
    assert bump_at("2.32.4", 2) == "2.33"
    assert bump_at("2.32.4", 3) == "2.32.5"
    assert bump_at("2.32.4", 1) == "3"


def _fixture_plan(name: str, releases: dict[str, list[str]]) -> tuple[Path, object]:
    project = detect_project(FIXTURES / "uv" / name)
    graph = load_graph(project)
    findings = annotate(merge_findings(parse_osv_json(osv_data(name))), graph)
    plan = build_plan(
        findings,
        graph,
        (project.root / "pyproject.toml").read_text("utf-8"),
        project.lockfile,
        StaticIndex(releases),
        allow_major=False,
    )
    return project.root, plan


def test_fixture_plans() -> None:
    _, plan = _fixture_plan("direct-pinned", {"requests": ["2.31.0", "2.32.4", "2.33.0", "2.34.2"]})
    [u] = plan.upgrades  # type: ignore[attr-defined]
    assert (u.package, u.method) == ("requests", "raise-bound")
    _, plan = _fixture_plan("transitive", {"urllib3": ["2.2.1", "2.5.0", "2.8.0"]})
    [u] = plan.upgrades  # type: ignore[attr-defined]
    assert (u.package, u.method, u.to_version) == ("urllib3", "lock-upgrade", "2.8.0")
    _, plan = _fixture_plan("major-only", {"urllib3": ["1.26.20", "2.8.0"]})
    assert plan.upgrades == []  # type: ignore[attr-defined]
    assert all("major" in r for r in plan.no_fix.values())  # type: ignore[attr-defined]


def test_ride_along_moves_up_within_the_major_only() -> None:
    # A (high, fixed 1.4.2) is in scope; B (medium, fixed 1.5.0) rides along.
    target, fixed, _ = choose_target("1.4.0", [A], RELEASES[1:], allow_major=False)
    assert target == "1.4.2"
    new_target, riding = ride_along(target, fixed, [B], RELEASES[1:])
    assert (new_target, [f.advisory_id for f in riding]) == ("1.5.0", ["CVE-B"])
    # C needs 2.x: it does not ride, and the in-scope target is unchanged.
    assert ride_along(target, fixed, [C], RELEASES[1:]) == ("1.4.2", [])


def test_riders_never_change_the_in_scope_fix() -> None:
    _, fixed, _ = choose_target("1.4.0", [B], RELEASES[1:], allow_major=False)
    target, riding = ride_along("1.5.0", fixed, [A, C], RELEASES[1:])
    assert target == "1.5.0" and [f.advisory_id for f in riding] == ["CVE-A"]


def test_calendar_versions_are_not_majors() -> None:
    assert not is_major_upgrade("2025.11.12", "2026.10.18")  # certifi
    assert not is_major_upgrade("2024.1", "2025.2")  # pytz / tzdata
    assert is_major_upgrade("0.50.0", "1.0.1")  # starlette
    assert is_major_upgrade("12.3.0", "13.0.0")
    assert not is_major_upgrade("2.31.0", "2.33.0")
    certifi = adv("CVE-CERT", ("0", "2026.10.18"))
    target, _, reasons = choose_target(
        "2025.11.12", [certifi], ["2026.1.1", "2026.10.18"], allow_major=False
    )
    assert target == "2026.10.18" and reasons == {}
