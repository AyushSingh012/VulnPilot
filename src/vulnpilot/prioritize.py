"""Order findings most urgent first: known exploited, then likely exploited, then severity.

1. In CISA KEV (exploited in the wild).
2. EPSS at or above 0.1 (likely to be exploited soon).
3. Severity, CRITICAL first; unrated counts as HIGH.
4. Then the EPSS score, then CVSS, so equal severities still break by real-world risk.

Within the same severity, the more likely exploited finding comes first.
"""

from __future__ import annotations

from vulnpilot.models import Finding, Severity

EPSS_LIKELY = 0.1
"""EPSS probability at or above which a finding counts as likely to be exploited."""


def gate_severity(f: Finding) -> Severity:
    """Severity used for the threshold and ordering: unrated counts as HIGH until rated."""
    return Severity.HIGH if f.severity is Severity.UNKNOWN else f.severity


def always_fix(f: Finding) -> bool:
    """Known or likely exploitation outranks the severity threshold."""
    return f.in_kev or (f.epss or 0.0) >= EPSS_LIKELY


def sort_key(f: Finding) -> tuple[bool, bool, int, float, str, float, str]:
    return (
        not f.in_kev,
        (f.epss or 0.0) < EPSS_LIKELY,
        -gate_severity(f).rank,
        -(f.epss or 0.0),
        f.package,
        -(f.cvss or 0.0),
        f.advisory_id,
    )
