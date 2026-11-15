"""CISA Known Exploited Vulnerabilities catalog, downloaded at most once a day."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_AGE = timedelta(hours=24)


def _read_cache(path: Path) -> tuple[set[str], datetime] | None:
    try:
        data = json.loads(path.read_text("utf-8"))
        return set(data["cves"]), datetime.fromisoformat(data["fetched_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def load_kev(client: httpx.Client, cache: Path, now: datetime) -> tuple[set[str], str | None]:
    """CVE IDs in the KEV catalog, and a warning if they could not be refreshed."""
    cached = _read_cache(cache)
    if cached and now - cached[1] < MAX_AGE:
        return cached[0], None
    try:
        response = client.get(KEV_URL)
        response.raise_for_status()
        ids = {str(v["cveID"]) for v in response.json().get("vulnerabilities", [])}
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        if cached:
            day = cached[1].date().isoformat()
            return cached[0], f"could not refresh the CISA KEV catalog; using the copy from {day}"
        return set(), "could not download the CISA KEV catalog; KEV status is unknown this run"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"fetched_at": now.isoformat(), "cves": sorted(ids)}), "utf-8")
    return ids, None
