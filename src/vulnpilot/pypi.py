"""Which releases of a package exist and are not yanked (PyPI JSON API)."""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from vulnpilot import __version__
from vulnpilot.versions import parse, sort_versions

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
TIMEOUT_S = 15.0


class ReleaseIndex(Protocol):
    def releases(self, package: str) -> list[str] | None:
        """Final, non-yanked versions, lowest first; None when the index can't be reached."""
        ...


def usable_releases(data: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for version, files in (data.get("releases") or {}).items():
        v = parse(version)
        if v is None or v.is_prerelease or v.is_devrelease or not files:
            continue
        if all(f.get("yanked") for f in files):
            continue
        out.append(version)
    return sort_versions(out)


class PyPIIndex:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            timeout=TIMEOUT_S, headers={"User-Agent": f"vulnpilot/{__version__}"}
        )
        self._cache: dict[str, list[str] | None] = {}

    def releases(self, package: str) -> list[str] | None:
        if package not in self._cache:
            try:
                resp = self._client.get(PYPI_JSON.format(name=package))
                resp.raise_for_status()
                self._cache[package] = usable_releases(resp.json())
            except (httpx.HTTPError, ValueError):
                self._cache[package] = None
        return self._cache[package]


class StaticIndex:
    """For tests and offline runs."""

    def __init__(self, releases: dict[str, list[str]] | None = None) -> None:
        self._releases = releases or {}

    def releases(self, package: str) -> list[str] | None:
        found = self._releases.get(package)
        return sort_versions(found) if found is not None else None
