"""FIRST EPSS scores, looked up 100 CVEs at a time and cached per CVE for a day."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH = 100
MAX_AGE = timedelta(hours=24)

# cve -> [score or None (no EPSS entry), fetched_at]
_Cache = dict[str, list[object]]


def _read_cache(path: Path) -> _Cache:
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _fresh(entry: list[object], now: datetime) -> bool:
    try:
        return now - datetime.fromisoformat(str(entry[1])) < MAX_AGE
    except (ValueError, IndexError):
        return False


def lookup_epss(
    cves: list[str], client: httpx.Client, cache: Path, now: datetime
) -> tuple[dict[str, float | None], str | None]:
    """EPSS probability per CVE (None = no score published), and a warning if offline."""
    stored = _read_cache(cache)
    wanted = [c for c in cves if c not in stored or not _fresh(stored[c], now)]
    failed = False
    for i in range(0, len(wanted), BATCH):
        batch = wanted[i : i + BATCH]
        try:
            response = client.get(EPSS_URL, params={"cve": ",".join(batch)})
            response.raise_for_status()
            rows = response.json().get("data", [])
        except (httpx.HTTPError, ValueError):
            failed = True
            break
        got = {str(r["cve"]): float(r["epss"]) for r in rows if "cve" in r and "epss" in r}
        for c in batch:
            stored[c] = [got.get(c), now.isoformat()]
    if wanted and not failed:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(stored), "utf-8")
    scores: dict[str, float | None] = {}
    for c in cves:
        entry = stored.get(c)
        scores[c] = float(entry[0]) if entry and isinstance(entry[0], (int, float)) else None
    warning = (
        "could not reach the FIRST EPSS API; EPSS scores are missing or out of date this run"
        if failed
        else None
    )
    return scores, warning
