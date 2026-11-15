"""Find upgrades that break the tests by bisection.

Invariant while searching: ``context`` passes and ``context + suspects`` fails. Each round
tests ``context + first half``: if it fails the breaker is in the first half, otherwise the
first half joins the context and the breaker is in the second half. That is about log2(N)
test runs per breaker, and it also finds breakers that only fail in combination.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from vulnpilot.models import Upgrade, ValidationResult

TestFn = Callable[[list[Upgrade]], ValidationResult]


@dataclass
class Isolation:
    kept: list[Upgrade]
    final: ValidationResult | None
    """The passing run of exactly ``kept`` (None when nothing was kept)."""
    breakers: dict[str, ValidationResult] = field(default_factory=dict)
    """package -> the failing run that convicted it."""
    test_runs: int = 0


def isolate_breakers(upgrades: list[Upgrade], test: TestFn) -> Isolation:
    runs = 0

    def check(items: list[Upgrade]) -> ValidationResult:
        nonlocal runs
        runs += 1
        return test(items)

    remaining = list(upgrades)
    breakers: dict[str, ValidationResult] = {}
    while remaining:
        result = check(remaining)
        if result.passed:
            return Isolation(remaining, result, breakers, runs)
        context: list[Upgrade] = []
        suspects = remaining
        evidence = result
        while len(suspects) > 1:
            half = len(suspects) // 2
            first, second = suspects[:half], suspects[half:]
            trial = check(context + first)
            if not trial.passed:
                suspects, evidence = first, trial
            else:
                context, suspects = context + first, second
        breaker = suspects[0]
        breakers[breaker.package] = evidence
        remaining = [u for u in remaining if u.package != breaker.package]
    return Isolation([], None, breakers, runs)
