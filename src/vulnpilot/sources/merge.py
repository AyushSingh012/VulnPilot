"""Merge findings from all sources and attach dependency information.

Two findings are the same issue when they are for the same package (and installed
version) and their advisory IDs overlap, followed transitively: if A shares an ID with
B and B with C, all three are one finding.
"""

from __future__ import annotations

from collections import defaultdict

from packaging.version import InvalidVersion, Version

from vulnpilot.lockgraph import LockGraph
from vulnpilot.models import Finding, finding_key, normalize_package
from vulnpilot.sources.osv import preferred_id


def _sort_versions(versions: set[str]) -> list[str]:
    def key(v: str) -> tuple[int, Version | str]:
        try:
            return (0, Version(v))
        except InvalidVersion:
            return (1, v)

    return sorted(versions, key=key)


def _combine(items: list[Finding]) -> Finding:
    first = items[0]
    aliases = sorted({a for f in items for a in f.aliases})
    severity = max((f.severity for f in items), key=lambda s: s.rank)
    scores = [f.cvss for f in items if f.cvss is not None]
    refs: dict[str, None] = {}
    for f in items:
        for r in f.references:
            refs.setdefault(r, None)
    return first.model_copy(
        update={
            "key": finding_key(first.ecosystem, first.package, aliases),
            "advisory_id": preferred_id(aliases),
            "aliases": aliases,
            "fixed_versions": _sort_versions({v for f in items for v in f.fixed_versions}),
            "in_lockfile": any(f.in_lockfile for f in items),
            "severity": severity,
            "cvss": max(scores) if scores else None,
            "references": list(refs),
            "sources": [s for f in items for s in f.sources],
        }
    )


def merge_findings(findings: list[Finding]) -> list[Finding]:
    buckets: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[(f.ecosystem, normalize_package(f.package), f.installed_version)].append(f)

    merged: list[Finding] = []
    for items in buckets.values():
        merged.extend(_combine(group) for group in _alias_groups(items))
    return merged


def _find(parent: list[int], i: int) -> int:
    while parent[i] != i:
        parent[i] = parent[parent[i]]
        i = parent[i]
    return i


def _alias_groups(items: list[Finding]) -> list[list[Finding]]:
    """Union-find over shared advisory IDs."""
    parent = list(range(len(items)))
    owner: dict[str, int] = {}
    for i, f in enumerate(items):
        for alias in f.aliases:
            if alias in owner:
                parent[_find(parent, i)] = _find(parent, owner[alias])
            else:
                owner[alias] = i
    groups: dict[int, list[Finding]] = defaultdict(list)
    for i, f in enumerate(items):
        groups[_find(parent, i)].append(f)
    return list(groups.values())


def annotate(findings: list[Finding], graph: LockGraph) -> list[Finding]:
    """Mark direct / dev-only and record how each vulnerable package is pulled in."""
    return [
        f.model_copy(
            update={
                "is_direct": graph.is_direct(f.package),
                "dev_only": graph.is_dev_only(f.package),
                "dependency_paths": graph.paths_to(f.package),
            }
        )
        for f in findings
    ]
