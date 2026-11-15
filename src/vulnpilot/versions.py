"""Version helpers shared by the planner and the specifier editor."""

from __future__ import annotations

from collections.abc import Iterable

from packaging.version import InvalidVersion, Version

from vulnpilot.models import Finding, VersionRange


def parse(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def major(text: str) -> int | None:
    v = parse(text)
    return v.major if v else None


def sort_versions(versions: Iterable[str]) -> list[str]:
    parsed = [(pv, v) for v in set(versions) if (pv := parse(v)) is not None]
    return [v for _, v in sorted(parsed)]


def in_range(version: Version, rng: VersionRange) -> bool:
    lo = parse(rng.introduced) if rng.introduced not in ("", "0") else None
    if lo is not None and version < lo:
        return False
    if rng.fixed is not None:
        hi = parse(rng.fixed)
        return hi is None or version < hi
    if rng.last_affected is not None:
        last = parse(rng.last_affected)
        return last is None or version <= last
    return True


def is_affected(version: str, finding: Finding) -> bool:
    """Is ``version`` still affected by this finding's advisory?

    Uses the advisory's ranges when known. Otherwise (e.g. an imported file with only a
    fixed version) anything below the lowest known fixed version counts as affected.
    """
    v = parse(version)
    if v is None:
        return True
    if finding.affected_ranges:
        return any(in_range(v, r) for r in finding.affected_ranges)
    if not finding.fixed_versions:
        return True
    lowest = parse(finding.fixed_versions[0])
    return lowest is None or v < lowest


def bump_at(version: str, components: int) -> str:
    """Smallest version above ``version`` at a given granularity: (2.32.4, 2) -> 2.33."""
    v = parse(version)
    if v is None:
        raise ValueError(f"not a version: {version}")
    parts = [*v.release, 0, 0, 0][: max(components, 1)]
    parts[-1] += 1
    return ".".join(str(p) for p in parts)
