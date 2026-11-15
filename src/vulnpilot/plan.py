"""Pick a target version for each vulnerable package.

Rules (see the plan, step 6):
- If an allowed version fixes all of a package's advisories, pick the lowest non-yanked one.
- Otherwise pick the lowest version in the current major that fixes the most advisories
  (a partial fix); the rest are NO_SAFE_FIX ("needs a major upgrade").
- If nothing fixes any of them, the package is NO_SAFE_FIX.
- Ride-along: when a package is upgraded anyway, its below-threshold advisories are fixed
  too if the target, or a later version in the same major, also fixes them. They never
  change which in-scope advisories get fixed, and are never reported as NO_SAFE_FIX.
"""

from __future__ import annotations

import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from vulnpilot.lockgraph import LockGraph
from vulnpilot.models import Finding, Upgrade, normalize_package
from vulnpilot.pypi import ReleaseIndex
from vulnpilot.specifiers import allows
from vulnpilot.versions import is_affected, major, parse, sort_versions


@dataclass
class Plan:
    upgrades: list[Upgrade] = field(default_factory=list)
    no_fix: dict[str, str] = field(default_factory=dict)
    """finding key -> plain-words reason it gets NO_SAFE_FIX."""
    warnings: list[str] = field(default_factory=list)


def registry_packages(lockfile: Path) -> set[str]:
    """Packages that come from a package index (not a path, git or URL source)."""
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    return {
        normalize_package(p["name"])
        for p in data.get("package", [])
        if "registry" in (p.get("source") or {})
    }


def candidates(
    package: str, installed: str, findings: list[Finding], index: ReleaseIndex
) -> tuple[list[str], bool]:
    """Versions above ``installed`` to consider, and whether they came from the index."""
    current = parse(installed)
    allow_pre = bool(current and current.is_prerelease)
    released = index.releases(package)
    from_index = released is not None
    pool = released if released is not None else [v for f in findings for v in f.fixed_versions]
    out = []
    for text in sort_versions(pool):
        v = parse(text)
        if v is None or current is None or v <= current:
            continue
        if v.is_prerelease and not allow_pre:
            continue
        out.append(text)
    return out, from_index


def choose_target(
    installed: str, findings: list[Finding], cands: list[str], allow_major: bool
) -> tuple[str | None, list[Finding], dict[str, str]]:
    """Return (target, fixed findings, {unfixed key: reason})."""
    cur_major = major(installed)
    allowed = [c for c in cands if allow_major or major(c) == cur_major]

    def fixed_by(c: str) -> list[Finding]:
        return [f for f in findings if not is_affected(c, f)]

    target: str | None = None
    fixed: list[Finding] = []
    for c in allowed:
        hit = fixed_by(c)
        if len(hit) == len(findings):
            target, fixed = c, hit
            break
        if len(hit) > len(fixed):
            target, fixed = c, hit

    reasons: dict[str, str] = {}
    fixed_keys = {f.key for f in fixed}
    for f in findings:
        if f.key in fixed_keys:
            continue
        anywhere = next((c for c in cands if not is_affected(c, f)), None)
        if anywhere is not None and not allow_major and major(anywhere) != cur_major:
            reasons[f.key] = f"needs a major upgrade (fixed in {anywhere}); majors are not allowed"
        elif anywhere is not None:
            reasons[f.key] = f"fixed in {anywhere}, but no single version fixes it with the rest"
        else:
            reasons[f.key] = "no fixed version has been released"
    return target, fixed, reasons


def ride_along(
    target: str, fixed: list[Finding], extras: list[Finding], cands: list[str]
) -> tuple[str, list[Finding]]:
    """A target in the same major that also fixes extras, without losing any fixed finding.

    Prefers the lowest version that fixes every extra; else keeps ``target`` and whichever
    extras it already fixes.
    """
    if not extras:
        return target, []
    tv = parse(target)
    same_major = [
        c for c in cands if major(c) == major(target) and (p := parse(c)) and tv and p >= tv
    ]
    for c in same_major:
        if all(not is_affected(c, f) for f in [*fixed, *extras]):
            return c, extras
    return target, [f for f in extras if not is_affected(target, f)]


def build_plan(
    findings: list[Finding],
    graph: LockGraph,
    pyproject_text: str,
    lockfile: Path,
    index: ReleaseIndex,
    allow_major: bool,
    extras: list[Finding] | None = None,
) -> Plan:
    """Plan upgrades for ``findings``; ``extras`` (below the threshold) only ride along."""
    plan = Plan()
    from_registry = registry_packages(lockfile)
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.in_lockfile and not f.fixed_in_source:
            groups[(normalize_package(f.package), f.installed_version)].append(f)
    riders: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in extras or []:
        key = (normalize_package(f.package), f.installed_version)
        if f.in_lockfile and not f.fixed_in_source and key in groups:
            riders[key].append(f)

    for (package, installed), items in sorted(groups.items()):
        if package not in from_registry:
            for f in items:
                plan.no_fix[f.key] = "installed from a path, git or URL source, not an index"
            continue
        cands, from_index = candidates(
            package, installed, [*items, *riders[(package, installed)]], index
        )
        if not from_index:
            plan.warnings.append(
                f"could not read {package}'s releases from the index; "
                "using advisory fixed versions without a yanked check"
            )
        target, fixed, reasons = choose_target(installed, items, cands, allow_major)
        plan.no_fix.update(reasons)
        if target is None:
            continue
        target, riding = ride_along(target, fixed, riders[(package, installed)], cands)
        is_direct = graph.is_direct(package)
        if is_direct and not allows(pyproject_text, package, target):
            method = "raise-bound"
        else:
            method = "lock-upgrade"
        plan.upgrades.append(
            Upgrade(
                package=package,
                from_version=installed,
                to_version=target,
                method=method,
                finding_keys=[f.key for f in [*fixed, *riding]],
                unfixed_keys=list(reasons),
            )
        )
    return plan
