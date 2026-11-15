"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF viewers.

One rule per advisory, one result per finding. Each result points at the package's entry
in the lockfile; findings that exist only in an image point at the lockfile without a line.
``partialFingerprints`` carries the finding key, so a finding keeps its identity across runs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vulnpilot import __version__
from vulnpilot.models import Finding, FixResult, FixStatus, Severity
from vulnpilot.prioritize import gate_severity

SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
_OSV = "https://osv.dev/vulnerability/"
# GitHub reads security-severity (a CVSS-like 0-10 string) to bucket alerts.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _package_lines(lockfile: Path) -> dict[str, int]:
    """1-based line of each ``name = "pkg"`` entry in a uv.lock / poetry.lock."""
    lines: dict[str, int] = {}
    try:
        text = lockfile.read_text("utf-8")
    except OSError:
        return lines
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.match(r'^name = "([^"]+)"', line)
        if m:
            lines.setdefault(m.group(1).lower().replace("_", "-").replace(".", "-"), i)
    return lines


def _rule(f: Finding) -> dict[str, Any]:
    sev = gate_severity(f)
    score = f"{f.cvss:.1f}" if f.cvss is not None else _SECURITY_SEVERITY[sev]
    return {
        "id": f.advisory_id,
        "name": f.advisory_id.replace("-", ""),
        "shortDescription": {"text": f"{f.advisory_id} in {f.package}"},
        "helpUri": f"{_OSV}{f.advisory_id}",
        "help": {"text": f"See {_OSV}{f.advisory_id}. Aliases: {', '.join(f.aliases)}."},
        "properties": {
            "security-severity": score,
            "tags": ["security", "vulnerability", "dependency"],
        },
    }


def _message(f: Finding, status: FixResult | None) -> str:
    fixed = f"; fixed in {f.fixed_versions[0]}" if f.fixed_versions else "; no fixed version"
    text = f"{f.package} {f.installed_version} is affected by {f.advisory_id}{fixed}."
    image = next((h.target for h in f.sources if h.target.startswith("image:")), None)
    if image and not f.in_lockfile:
        text += f" Found in {image.removeprefix('image:')}, not in the lockfile."
    if status is not None:
        text += f" VulnPilot: {status.status.value}" + (f" ({status.note})" if status.note else "")
    return text


def build_sarif(
    findings: list[Finding],
    lockfile: Path,
    lockfile_uri: str,
    statuses: dict[str, FixResult] | None = None,
) -> dict[str, Any]:
    lines = _package_lines(lockfile)
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rules.setdefault(f.advisory_id, _rule(f))
        region = {"startLine": lines[f.package]} if f.in_lockfile and f.package in lines else None
        physical: dict[str, Any] = {"artifactLocation": {"uri": lockfile_uri}}
        if region:
            physical["region"] = region
        status = (statuses or {}).get(f.key)
        results.append(
            {
                "ruleId": f.advisory_id,
                "level": _LEVEL[gate_severity(f)],
                "message": {"text": _message(f, status)},
                "locations": [{"physicalLocation": physical}],
                "partialFingerprints": {"vulnpilotFindingKey/v1": f.key},
                "properties": {
                    "package": f.package,
                    "installedVersion": f.installed_version,
                    "fixedVersions": f.fixed_versions,
                    "severity": f.severity.value,
                    "kev": f.in_kev,
                    "epss": f.epss,
                    "sources": sorted({h.tool for h in f.sources}),
                    **({"status": status.status.value} if status else {}),
                },
            }
        )
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnPilot",
                        "semanticVersion": __version__.split(".dev")[0],
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def remaining(findings: list[Finding], results: list[FixResult]) -> list[Finding]:
    """After a fix run: the findings still open (not fixed, not skipped)."""
    open_keys = {
        r.finding_key
        for r in results
        if not r.status.counts_as_fixed and r.status is not FixStatus.SKIPPED
    }
    return [f for f in findings if f.key in open_keys]


def write_sarif(payload: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
