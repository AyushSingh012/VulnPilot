"""OSV-Scanner adapter: run it on the lockfile and turn its JSON into findings."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from vulnpilot import proc
from vulnpilot.doctor import parse_version
from vulnpilot.models import Finding, Project, Severity, SourceHit, finding_key, normalize_package
from vulnpilot.proc import Runner, ToolNotFoundError, ToolTimeoutError
from vulnpilot.sources.base import SourceError

TOOL = "osv-scanner"
EXIT_NO_VULNS = 0
EXIT_VULNS_FOUND = 1
SCAN_TIMEOUT_S = 300
MAX_REFERENCES = 10

_GHSA_SEVERITY = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}
_ID_PREFERENCE = ("CVE-", "GHSA-", "PYSEC-")


def preferred_id(ids: Iterable[str]) -> str:
    """CVE first, then GHSA, then PYSEC, then anything else; lowest within a kind."""
    ordered = sorted(set(ids))
    for prefix in _ID_PREFERENCE:
        for advisory in ordered:
            if advisory.startswith(prefix):
                return advisory
    return ordered[0]


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _fixed_versions(vuln: dict[str, Any], package: str) -> set[str]:
    fixed: set[str] = set()
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or normalize_package(pkg.get("name", "")) != package:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            fixed.update(e["fixed"] for e in rng.get("events", []) if "fixed" in e)
    return fixed


def _sorted_versions(versions: Iterable[str]) -> list[str]:
    parsed = [(pv, v) for v in set(versions) if (pv := _version(v)) is not None]
    return [v for _, v in sorted(parsed)]


def _severity(group: dict[str, Any], vulns: list[dict[str, Any]]) -> tuple[Severity, float | None]:
    raw = str(group.get("max_severity") or "").strip()
    try:
        score = float(raw) if raw else None
    except ValueError:
        score = None
    if score is not None:
        return Severity.from_cvss(score), score
    best = Severity.UNKNOWN
    for vuln in vulns:
        label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        sev = _GHSA_SEVERITY.get(label, Severity.UNKNOWN)
        if sev.rank > best.rank:
            best = sev
    return best, None


def _references(vulns: list[dict[str, Any]]) -> list[str]:
    refs = [r for v in vulns for r in v.get("references", []) if r.get("url")]
    refs.sort(key=lambda r: r.get("type") != "ADVISORY")
    seen: dict[str, None] = {}
    for ref in refs:
        seen.setdefault(ref["url"], None)
    return list(seen)[:MAX_REFERENCES]


def parse_osv_json(data: dict[str, Any], tool_version: str | None = None) -> list[Finding]:
    """Turn ``osv-scanner --format json`` output into one Finding per advisory group."""
    findings: list[Finding] = []
    for result in data.get("results") or []:
        for entry in result.get("packages") or []:
            pkg = entry["package"]
            if pkg.get("ecosystem") != "PyPI":
                continue
            name = normalize_package(pkg["name"])
            installed = pkg["version"]
            installed_v = _version(installed)
            vulns_by_id = {v["id"]: v for v in entry.get("vulnerabilities") or []}
            groups = entry.get("groups") or [{"ids": [i]} for i in vulns_by_id]
            for group in groups:
                vulns = [vulns_by_id[i] for i in group.get("ids", []) if i in vulns_by_id]
                aliases = set(group.get("ids", [])) | set(group.get("aliases", []))
                for vuln in vulns:
                    aliases.update(vuln.get("aliases", []))
                if not aliases:
                    continue
                fixed: set[str] = set()
                for vuln in vulns:
                    fixed |= _fixed_versions(vuln, name)
                relevant = [
                    f
                    for f in _sorted_versions(fixed)
                    if installed_v is None or (_version(f) or installed_v) > installed_v
                ]
                severity, score = _severity(group, vulns)
                alias_list = sorted(aliases)
                hit = SourceHit(
                    source="osv",
                    tool=TOOL,
                    tool_version=tool_version,
                    target="source",
                    raw_id=group.get("ids", alias_list)[0],
                    severity=severity,
                    installed_version=installed,
                    fixed_version=relevant[0] if relevant else None,
                )
                findings.append(
                    Finding(
                        key=finding_key("PyPI", name, alias_list),
                        advisory_id=preferred_id(alias_list),
                        aliases=alias_list,
                        ecosystem="PyPI",
                        package=name,
                        installed_version=installed,
                        fixed_versions=relevant,
                        in_lockfile=True,
                        severity=severity,
                        cvss=score,
                        references=_references(vulns),
                        sources=[hit],
                    )
                )
    return findings


class OsvSource:
    name = "osv"

    def __init__(self, raw_dir: Path, run: Runner | None = None) -> None:
        self.raw_dir = raw_dir
        self._run = run

    def _exec(self, cmd: list[str], cwd: Path | None = None) -> proc.ProcResult:
        if self._run is not None:
            return self._run(cmd)
        return proc.run(cmd, cwd=cwd, timeout=SCAN_TIMEOUT_S)

    def tool_version(self) -> str | None:
        try:
            result = self._exec([TOOL, "--version"])
        except (ToolNotFoundError, ToolTimeoutError):
            return None
        return parse_version(result.stdout) if result.ok else None

    def collect(self, project: Project) -> list[Finding]:
        cmd = [TOOL, "scan", "source", "-L", str(project.lockfile), "--format", "json"]
        try:
            result = self._exec(cmd, cwd=project.root)
        except ToolNotFoundError as exc:
            raise SourceError(f"{TOOL} is not installed; run `vulnpilot doctor`") from exc
        except ToolTimeoutError as exc:
            raise SourceError(f"{TOOL} timed out after {SCAN_TIMEOUT_S}s") from exc
        if result.returncode not in (EXIT_NO_VULNS, EXIT_VULNS_FOUND):
            detail = (result.stderr.strip().splitlines() or ["no error output"])[-1]
            raise SourceError(f"{TOOL} failed (exit {result.returncode}): {detail}")
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise SourceError(f"{TOOL} did not return valid JSON") from exc
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        (self.raw_dir / "osv-scanner.json").write_text(result.stdout, encoding="utf-8")
        return parse_osv_json(data, self.tool_version())
