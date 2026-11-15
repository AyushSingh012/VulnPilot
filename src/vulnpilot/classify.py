"""Give every finding exactly one result state."""

from __future__ import annotations

from vulnpilot.config import IgnoreRule
from vulnpilot.models import (
    ExitCode,
    Finding,
    FixResult,
    FixStatus,
    Upgrade,
    ValidationResult,
    normalize_package,
)
from vulnpilot.plan import Plan


def same_issue(a: Finding, b: Finding) -> bool:
    """Same package and overlapping advisory IDs. The version is deliberately ignored."""
    return normalize_package(a.package) == normalize_package(b.package) and bool(
        set(a.aliases) & set(b.aliases)
    )


def _tests_note(result: ValidationResult) -> str:
    names = ", ".join(result.failed_tests) or "tests failed"
    return f"breaks tests: {names}"


def classify(
    shown: list[Finding],
    ignored: list[tuple[Finding, IgnoreRule]],
    below_threshold: list[Finding],
    plan: Plan,
    kept: list[Upgrade],
    breakers: dict[str, ValidationResult],
    blocked: dict[str, str],
    before_all: list[Finding],
    after_shown: list[Finding],
    tests_ran: bool,
    *,
    after_all: list[Finding] | None = None,
) -> list[FixResult]:
    """``after_*`` must already exclude findings the lockfile now fixes (fixed_in_source)."""
    results: list[FixResult] = []
    planned = {u.package: u for u in plan.upgrades}
    applied = {u.package: u for u in kept}
    fixed_status = FixStatus.FIXED_AND_VALIDATED if tests_ran else FixStatus.FIXED_NOT_TESTED
    after_everything = after_all if after_all is not None else after_shown
    for f, rule in ignored:
        results.append(
            FixResult(
                finding_key=f.key,
                status=FixStatus.SKIPPED,
                note=f"ignored in config until {rule.expires}: {rule.reason}",
            )
        )
    for f in below_threshold:
        up = applied.get(normalize_package(f.package))
        rode = up is not None and f.key in up.finding_keys
        if rode and not any(same_issue(f, a) for a in after_everything):
            results.append(
                FixResult(
                    finding_key=f.key,
                    status=fixed_status,
                    upgrade=up,
                    note="below the threshold; fixed by the same upgrade",
                )
            )
        else:
            results.append(
                FixResult(
                    finding_key=f.key, status=FixStatus.SKIPPED, note="below severity threshold"
                )
            )

    for f in shown:
        pkg = normalize_package(f.package)
        upgrade = applied.get(pkg) or planned.get(pkg)
        if f.fixed_in_source:
            status, note = (
                FixStatus.FIXED_IN_SOURCE,
                f"the lockfile already has {f.installed_version}; rebuild the image",
            )
        elif not f.in_lockfile:
            status, note = FixStatus.OUT_OF_SCOPE, "needs a base-image or Dockerfile change"
        elif f.key in plan.no_fix:
            status, note = FixStatus.NO_SAFE_FIX, plan.no_fix[f.key]
        elif upgrade is None:
            status, note = FixStatus.NO_SAFE_FIX, "no upgrade was planned"
        elif pkg in breakers:
            status, note = FixStatus.FIXED_BUT_TESTS_FAILED, _tests_note(breakers[pkg])
        elif pkg in blocked:
            status, note = FixStatus.STILL_PRESENT, blocked[pkg]
        elif pkg in applied:
            if any(same_issue(f, a) for a in after_shown):
                status, note = (
                    FixStatus.STILL_PRESENT,
                    f"still reported after upgrading to {upgrade.to_version}",
                )
            else:
                status, note = fixed_status, ""
                if upgrade.method == "parent-upgrade":
                    note = f"upgraded together with {', '.join(upgrade.parents)}"
        else:
            status, note = FixStatus.STILL_PRESENT, "upgrade was not applied"
        results.append(FixResult(finding_key=f.key, status=status, upgrade=upgrade, note=note))

    for a in after_shown:
        if not any(same_issue(a, b) for b in before_all):
            results.append(
                FixResult(
                    finding_key=a.key,
                    status=FixStatus.INTRODUCED,
                    note=f"{a.package} {a.installed_version} is affected by {a.advisory_id} "
                    "after the upgrades",
                )
            )
    return results


def exit_code(results: list[FixResult]) -> ExitCode:
    remaining = [
        r for r in results if r.status not in (FixStatus.SKIPPED,) and not r.status.counts_as_fixed
    ]
    return ExitCode.FINDINGS_REMAIN if remaining else ExitCode.OK
