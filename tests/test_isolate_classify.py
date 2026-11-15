from vulnpilot.classify import classify, exit_code, same_issue
from vulnpilot.isolate import TestFn, isolate_breakers
from vulnpilot.models import (
    ExitCode,
    Finding,
    FixStatus,
    Upgrade,
    ValidationResult,
    finding_key,
)
from vulnpilot.plan import Plan
from vulnpilot.validate import failed_test_names


def up(pkg: str) -> Upgrade:
    return Upgrade(
        package=pkg, from_version="1", to_version="2", method="lock-upgrade", finding_keys=[]
    )


def make_tester(
    breakers: set[str], pairs: frozenset[frozenset[str]] = frozenset()
) -> tuple[TestFn, list[list[str]]]:
    calls: list[list[str]] = []

    def test(items: list[Upgrade]) -> ValidationResult:
        names = {u.package for u in items}
        calls.append(sorted(names))
        bad = bool(names & breakers) or any(p <= names for p in pairs)
        return ValidationResult(ran=True, passed=not bad, failed_tests=["t::x"] if bad else [])

    return test, calls


def test_all_pass_in_one_run() -> None:
    test, calls = make_tester(set())
    iso = isolate_breakers([up(p) for p in "abcdefgh"], test)
    assert [u.package for u in iso.kept] == list("abcdefgh")
    assert iso.breakers == {} and len(calls) == 1


def test_single_breaker_found_by_bisection() -> None:
    test, calls = make_tester({"f"})
    iso = isolate_breakers([up(p) for p in "abcdefgh"], test)
    assert set(iso.breakers) == {"f"}
    assert [u.package for u in iso.kept] == list("abcdegh")
    assert iso.final is not None and iso.final.passed
    assert len(calls) <= 1 + 3 + 1  # full set, log2(8) halvings, final re-test


def test_two_breakers() -> None:
    test, _ = make_tester({"b", "g"})
    iso = isolate_breakers([up(p) for p in "abcdefgh"], test)
    assert set(iso.breakers) == {"b", "g"}
    assert len(iso.kept) == 6


def test_interaction_breaker() -> None:
    test, _ = make_tester(set(), pairs=frozenset({frozenset({"a", "e"})}))
    iso = isolate_breakers([up(p) for p in "abcdefgh"], test)
    assert set(iso.breakers) == {"e"}  # the later one of the pair is dropped
    assert "a" in {u.package for u in iso.kept}


def test_everything_breaks() -> None:
    test, _ = make_tester(set("ab"))
    iso = isolate_breakers([up("a"), up("b")], test)
    assert iso.kept == [] and iso.final is None and set(iso.breakers) == {"a", "b"}


def f(pkg: str, *ids: str, version: str = "1.0") -> Finding:
    return Finding(
        key=finding_key("PyPI", pkg, list(ids)),
        advisory_id=ids[0],
        aliases=list(ids),
        ecosystem="PyPI",
        package=pkg,
        installed_version=version,
    )


def test_classify_every_state() -> None:
    fixed, broke, blocked, nosafe, still = (
        f("a", "CVE-1"),
        f("b", "CVE-2"),
        f("c", "CVE-3"),
        f("d", "CVE-4"),
        f("e", "CVE-5"),
    )
    new = f("z", "CVE-9")
    plan = Plan(upgrades=[up("a"), up("b"), up("c"), up("e")], no_fix={nosafe.key: "needs a major"})
    after = [f("e", "GHSA-5", "CVE-5", version="2"), new]
    results = classify(
        [fixed, broke, blocked, nosafe, still],
        [],
        [],
        plan,
        kept=[up("a"), up("e")],
        breakers={"b": ValidationResult(ran=True, passed=False, failed_tests=["t::x"])},
        blocked={"c": "parent caps it"},
        before_all=[fixed, broke, blocked, nosafe, still],
        after_shown=after,
        tests_ran=True,
    )
    by_key = {r.finding_key: r for r in results}
    assert by_key[fixed.key].status is FixStatus.FIXED_AND_VALIDATED
    assert by_key[broke.key].status is FixStatus.FIXED_BUT_TESTS_FAILED
    assert "t::x" in by_key[broke.key].note
    assert by_key[blocked.key].status is FixStatus.STILL_PRESENT
    assert by_key[nosafe.key].status is FixStatus.NO_SAFE_FIX
    assert by_key[still.key].status is FixStatus.STILL_PRESENT  # same issue at the new version
    assert by_key[new.key].status is FixStatus.INTRODUCED
    assert exit_code(results) is ExitCode.FINDINGS_REMAIN


def test_untested_fix_and_clean_exit() -> None:
    a = f("a", "CVE-1")
    results = classify(
        [a], [], [], Plan(upgrades=[up("a")]), [up("a")], {}, {}, [a], [], tests_ran=False
    )
    assert results[0].status is FixStatus.FIXED_NOT_TESTED
    assert exit_code(results) is ExitCode.OK


def test_same_issue_ignores_version() -> None:
    assert same_issue(f("a", "CVE-1", version="1"), f("A", "GHSA-1", "CVE-1", version="2"))
    assert not same_issue(f("a", "CVE-1"), f("b", "CVE-1"))


def test_failed_test_names() -> None:
    out = (
        "....\nFAILED tests/t.py::test_a - assert 1\n"
        "ERROR tests/t.py::test_b\nFAILED tests/t.py::test_a\n"
    )
    assert failed_test_names(out) == ["tests/t.py::test_a", "tests/t.py::test_b"]


def test_rider_fixed_by_the_same_upgrade_counts_as_fixed() -> None:
    high, medium = f("a", "CVE-1"), f("a", "CVE-2")
    upgrade = Upgrade(
        package="a", from_version="1", to_version="2", method="lock-upgrade",
        finding_keys=[high.key, medium.key],
    )  # fmt: skip
    results = classify(
        [high], [], [medium], Plan(upgrades=[upgrade]), [upgrade], {}, {}, [high, medium], [],
        tests_ran=True, after_all=[],
    )  # fmt: skip
    by_key = {r.finding_key: r for r in results}
    assert by_key[medium.key].status is FixStatus.FIXED_AND_VALIDATED
    assert "same upgrade" in by_key[medium.key].note
    unrelated = f("b", "CVE-3")
    results = classify(
        [], [], [unrelated], Plan(), [], {}, {}, [unrelated], [], tests_ran=True, after_all=[]
    )
    assert results[0].status is FixStatus.SKIPPED


def test_image_finding_already_fixed_in_the_lockfile() -> None:
    img = f("a", "CVE-1", version="2.0")
    img.fixed_in_source = True
    [r] = classify([img], [], [], Plan(), [], {}, {}, [img], [], tests_ran=True)
    assert r.status is FixStatus.FIXED_IN_SOURCE and "rebuild the image" in r.note
