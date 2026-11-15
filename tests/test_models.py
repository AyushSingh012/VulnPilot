import pytest

from vulnpilot.models import FixStatus, Severity, finding_key, normalize_package


def test_key_has_no_version_and_is_alias_order_independent() -> None:
    a = finding_key("PyPI", "Jinja2", ["GHSA-h5c8-rqwp-cp95", "CVE-2024-22195"])
    b = finding_key("PyPI", "jinja2", ["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95"])
    assert a == b == "PyPI|jinja2|CVE-2024-22195"


def test_key_requires_an_advisory() -> None:
    with pytest.raises(ValueError, match="advisory"):
        finding_key("PyPI", "requests", [])


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("Jinja2", "jinja2"), ("charset_normalizer", "charset-normalizer"), ("Foo.Bar", "foo-bar")],
)
def test_normalize_package(raw: str, expected: str) -> None:
    assert normalize_package(raw) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, Severity.UNKNOWN),
        (0.0, Severity.UNKNOWN),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (9.8, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss(score: float | None, expected: Severity) -> None:
    assert Severity.from_cvss(score) is expected


def test_severity_ranks_are_ordered() -> None:
    ranks = [s.rank for s in (Severity.UNKNOWN, Severity.LOW, Severity.MEDIUM, Severity.HIGH)]
    assert ranks == sorted(ranks)
    assert Severity.CRITICAL.rank > Severity.HIGH.rank


def test_only_two_states_count_as_fixed() -> None:
    fixed = {s for s in FixStatus if s.counts_as_fixed}
    assert fixed == {FixStatus.FIXED_AND_VALIDATED, FixStatus.FIXED_NOT_TESTED}
