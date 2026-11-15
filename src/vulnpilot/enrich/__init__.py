"""Add exploitation signals to findings: CISA KEV (known exploited) and FIRST EPSS
(probability of exploitation in the next 30 days).

Only CVE IDs leave the machine. Results are cached for 24 hours under the VulnPilot cache
folder. Offline, a stale cache is used if there is one; otherwise the run goes on without
the signal and says so. ``enrich: false`` in vulnpilot.yml turns this off.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import httpx

from vulnpilot import __version__
from vulnpilot.enrich.epss import lookup_epss
from vulnpilot.enrich.kev import load_kev
from vulnpilot.models import Finding

OFFLINE_ENV = "VULNPILOT_OFFLINE"
TIMEOUT_S = 20.0


def cves(findings: list[Finding]) -> list[str]:
    return sorted({a for f in findings for a in f.aliases if a.startswith("CVE-")})


def enrich(
    findings: list[Finding],
    cache: Path,
    *,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Set ``in_kev`` and ``epss`` on ``findings`` in place; return warnings."""
    if os.environ.get(OFFLINE_ENV) == "1":
        return []
    ids = cves(findings)
    if not ids:
        return []
    now = now or datetime.now(UTC)
    own = client is None
    http = client or httpx.Client(
        timeout=TIMEOUT_S, headers={"User-Agent": f"vulnpilot/{__version__}"}
    )
    warnings: list[str] = []
    try:
        kev, warning = load_kev(http, cache / "kev.json", now)
        if warning:
            warnings.append(warning)
        scores, warning = lookup_epss(ids, http, cache / "epss.json", now)
        if warning:
            warnings.append(warning)
    finally:
        if own:
            http.close()
    for f in findings:
        ids_here = set(f.aliases)
        if ids_here & kev:
            f.in_kev = True
        found = [s for c in ids_here if (s := scores.get(c)) is not None]
        if found:
            f.epss = max([*found, f.epss or 0.0])
    return warnings
