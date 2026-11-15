from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from vulnpilot.enrich import enrich
from vulnpilot.enrich.epss import BATCH
from vulnpilot.models import Finding, Severity, finding_key
from vulnpilot.prioritize import sort_key

NOW = datetime(2026, 11, 15, 12, tzinfo=UTC)


def f(cve: str, severity: Severity = Severity.HIGH, pkg: str = "demo", **kw: object) -> Finding:
    return Finding(
        key=finding_key("PyPI", pkg, [cve]),
        advisory_id=cve,
        aliases=[cve, f"GHSA-{cve[-4:]}"],
        ecosystem="PyPI",
        package=pkg,
        installed_version="1.0",
        severity=severity,
        **kw,
    )


class Api:
    """Fake CISA + FIRST endpoints; counts calls; can go offline."""

    def __init__(self, kev: set[str], epss: dict[str, float]) -> None:
        self.kev, self.epss = kev, epss
        self.calls: list[str] = []
        self.offline = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.offline:
            raise httpx.ConnectError("offline", request=request)
        self.calls.append(request.url.host)
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": c} for c in self.kev]})
        asked = request.url.params["cve"].split(",")
        assert len(asked) <= BATCH
        rows = [{"cve": c, "epss": str(self.epss[c])} for c in asked if c in self.epss]
        return httpx.Response(200, json={"data": rows})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture(autouse=True)
def online(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULNPILOT_OFFLINE", raising=False)


def test_kev_and_epss_are_set_and_cached_for_a_day(tmp_path: Path) -> None:
    api = Api(kev={"CVE-2026-0001"}, epss={"CVE-2026-0001": 0.97, "CVE-2026-0002": 0.002})
    found = [f("CVE-2026-0001"), f("CVE-2026-0002"), f("CVE-2026-0003")]
    assert enrich(found, tmp_path, client=api.client(), now=NOW) == []
    assert [x.in_kev for x in found] == [True, False, False]
    assert [x.epss for x in found] == [0.97, 0.002, None]
    calls = len(api.calls)
    enrich([f("CVE-2026-0001")], tmp_path, client=api.client(), now=NOW + timedelta(hours=23))
    assert len(api.calls) == calls  # both served from the cache
    enrich([f("CVE-2026-0001")], tmp_path, client=api.client(), now=NOW + timedelta(hours=25))
    assert len(api.calls) == calls + 2


def test_epss_is_asked_in_batches_of_100(tmp_path: Path) -> None:
    ids = [f"CVE-2026-{i:05d}" for i in range(250)]
    api = Api(kev=set(), epss={c: 0.01 for c in ids})
    enrich([f(c) for c in ids], tmp_path, client=api.client(), now=NOW)
    assert api.calls.count("api.first.org") == 3


def test_offline_uses_the_old_cache_with_a_warning(tmp_path: Path) -> None:
    api = Api(kev={"CVE-2026-0001"}, epss={"CVE-2026-0001": 0.5})
    enrich([f("CVE-2026-0001")], tmp_path, client=api.client(), now=NOW)
    api.offline = True
    later = [f("CVE-2026-0001")]
    warnings = enrich(later, tmp_path, client=api.client(), now=NOW + timedelta(days=3))
    assert later[0].in_kev and later[0].epss == 0.5
    assert any("using the copy from 2026-11-15" in w for w in warnings)
    assert any("EPSS" in w for w in warnings)


def test_offline_with_no_cache_goes_on(tmp_path: Path) -> None:
    api = Api(kev=set(), epss={})
    api.offline = True
    found = [f("CVE-2026-0001")]
    warnings = enrich(found, tmp_path, client=api.client(), now=NOW)
    assert not found[0].in_kev and found[0].epss is None
    assert any("KEV status is unknown" in w for w in warnings)


def test_order_is_kev_then_likely_exploited_then_severity() -> None:
    critical = f("CVE-1", Severity.CRITICAL, pkg="a")
    kev_low = f("CVE-2", Severity.LOW, pkg="b", in_kev=True)
    likely_medium = f("CVE-3", Severity.MEDIUM, pkg="c", epss=0.4)
    high_low_epss = f("CVE-4", Severity.HIGH, pkg="d", epss=0.05)
    high_lower_epss = f("CVE-5", Severity.HIGH, pkg="e", epss=0.001)
    unrated = f("CVE-6", Severity.UNKNOWN, pkg="f")
    items = [high_lower_epss, unrated, critical, high_low_epss, likely_medium, kev_low]
    ordered = [x.advisory_id for x in sorted(items, key=sort_key)]
    assert ordered == ["CVE-2", "CVE-3", "CVE-1", "CVE-4", "CVE-5", "CVE-6"]
