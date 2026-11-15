"""Trivy and Wiz JSON files, scanned elsewhere (a repo or a container image), merged in.

Each vulnerability becomes a Finding for the package *as the lockfile has it*:

- a Python package the lockfile holds -> installed_version is the lockfile's version; if
  that version is no longer affected, the finding is ``fixed_in_source`` (the image was
  built before the fix: FIXED_IN_SOURCE);
- an OS package, another language, or a Python package the lockfile does not hold ->
  ``in_lockfile=False`` (OUT_OF_SCOPE).

Secret findings in either format are skipped: never parsed, printed or stored, and the
import file itself is never copied into the run folder.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from vulnpilot.models import (
    Finding,
    Severity,
    SourceHit,
    VersionRange,
    finding_key,
    normalize_package,
)
from vulnpilot.sources.base import SourceError
from vulnpilot.sources.osv import preferred_id
from vulnpilot.versions import is_affected

Tool = Literal["trivy", "wiz"]
Kind = Literal["repo", "image"]

# Trivy 0.69.4 to 0.69.6 were malicious releases (supply-chain compromise, March 2026).
_BAD_TRIVY = (Version("0.69.4"), Version("0.69.6"))
_TRIVY_PYTHON = {"python-pkg", "pip", "pipenv", "poetry", "uv", "conda-pkg"}
_PY_MARKERS = (".dist-info", ".egg-info", "site-packages", "dist-packages")
_PY_FILES = ("uv.lock", "poetry.lock", "requirements.txt", "pipfile.lock", "pyproject.toml")


class ImportFileError(SourceError):
    """An import file is missing, unreadable, or not a format VulnPilot knows."""


@dataclass
class ImportedFile:
    path: Path
    tool: Tool
    kind: Kind
    target: str
    """"source" for a repo scan, "image:<name>" for an image."""
    tool_version: str | None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def detect_format(data: Any) -> tuple[Tool, Kind]:
    if isinstance(data, dict) and "SchemaVersion" in data and "Results" in data:
        return "trivy", "image" if data.get("ArtifactType") == "container_image" else "repo"
    if isinstance(data, dict) and isinstance(data.get("result"), dict) and "status" in data:
        origin = str((data.get("scanOriginResource") or {}).get("__typename", ""))
        result = data["result"]
        is_image = "ContainerImage" in origin or (not origin and bool(result.get("osPackages")))
        return "wiz", "image" if is_image else "repo"
    raise ImportFileError("not a Trivy or Wiz JSON report")


def _severity(text: object) -> Severity:
    try:
        return Severity(str(text).upper())
    except ValueError:
        return Severity.UNKNOWN


def _fixed_list(text: object) -> list[str]:
    parts = [p.strip() for p in str(text or "").replace(";", ",").split(",")]
    return [p for p in parts if p]


def _ranges_from_fixed(fixed: list[str]) -> list[VersionRange]:
    """Approximate affected ranges from fixed versions on several release lines.

    "1.26.19, 2.2.2" -> [0, 1.26.19) and [2, 2.2.2): each later line starts at its major.
    """
    parsed: list[tuple[Version, str]] = []
    for f in fixed:
        try:
            parsed.append((Version(f), f))
        except InvalidVersion:
            continue
    parsed.sort()
    ranges = []
    for i, (v, text) in enumerate(parsed):
        start = "0" if i == 0 else str(v.major)
        ranges.append(VersionRange(introduced=start, fixed=text))
    return ranges


@dataclass(frozen=True)
class _Vuln:
    ecosystem: str
    package: str
    version: str
    advisory: str
    severity: Severity
    fixed: list[str]
    score: float | None = None
    epss: float | None = None
    kev: bool = False
    references: tuple[str, ...] = ()


def _trivy_vulns(data: dict[str, Any]) -> list[_Vuln]:
    out: list[_Vuln] = []
    for result in data.get("Results") or []:
        kind = str(result.get("Type", ""))
        if result.get("Class") == "os-pkgs":
            ecosystem = "os"  # same label as Wiz, so the two merge
        else:
            ecosystem = "PyPI" if kind in _TRIVY_PYTHON else kind or "unknown"
        for v in result.get("Vulnerabilities") or []:  # result["Secrets"] is never read
            scores = [
                float(s["V3Score"])
                for s in (v.get("CVSS") or {}).values()
                if isinstance(s, dict) and s.get("V3Score") is not None
            ]
            out.append(
                _Vuln(
                    ecosystem=ecosystem,
                    package=str(v.get("PkgName", "")),
                    version=str(v.get("InstalledVersion", "")),
                    advisory=str(v.get("VulnerabilityID", "")),
                    severity=_severity(v.get("Severity")),
                    fixed=_fixed_list(v.get("FixedVersion")),
                    score=max(scores) if scores else None,
                    references=tuple(str(r) for r in (v.get("References") or [])[:5]),
                )
            )
    return out


def _wiz_ecosystem(path: str) -> str:
    low = path.lower()
    if any(m in low for m in _PY_MARKERS) or low.endswith(_PY_FILES):
        return "PyPI"
    return "unknown"


def _wiz_vulns(data: dict[str, Any]) -> list[_Vuln]:
    result = data.get("result") or {}
    groups = [
        *[(p, "os") for p in result.get("osPackages") or []],
        *[(p, _wiz_ecosystem(str(p.get("path", "")))) for p in result.get("libraries") or []],
        *[(p, "cpe") for p in result.get("cpes") or []],
    ]  # result["secrets"] is never read
    out: list[_Vuln] = []
    for pkg, ecosystem in groups:
        for v in pkg.get("vulnerabilities") or []:
            epss = v.get("epssProbability")
            out.append(
                _Vuln(
                    ecosystem=ecosystem,
                    package=str(pkg.get("name", "")),
                    version=str(pkg.get("version", "")),
                    advisory=str(v.get("name", "")),
                    severity=_severity(v.get("severity")),
                    fixed=_fixed_list(v.get("fixedVersion")),
                    score=v.get("score"),
                    epss=float(epss) if epss is not None else None,
                    kev=bool(v.get("hasCisaKevExploit")),
                    references=(str(v["source"]),) if v.get("source") else (),
                )
            )
    return out


def _trivy_version(data: dict[str, Any]) -> str | None:
    version = (data.get("Trivy") or {}).get("Version")
    return str(version) if version else None


def _to_finding(
    v: _Vuln, tool: Tool, tool_version: str | None, source: str, target: str, lock: dict[str, str]
) -> Finding:
    name = normalize_package(v.package) if v.ecosystem == "PyPI" else v.package
    hit = SourceHit(
        source=source,
        tool=tool,
        tool_version=tool_version,
        target=target,
        raw_id=v.advisory,
        severity=v.severity,
        installed_version=v.version,
        fixed_version=v.fixed[0] if v.fixed else None,
    )
    locked = lock.get(name) if v.ecosystem == "PyPI" else None
    finding = Finding(
        key=finding_key(v.ecosystem, name, [v.advisory]),
        advisory_id=preferred_id([v.advisory]),
        aliases=[v.advisory],
        ecosystem=v.ecosystem,
        package=name,
        installed_version=locked or v.version,
        fixed_versions=v.fixed,
        affected_ranges=_ranges_from_fixed(v.fixed),
        in_lockfile=locked is not None,
        severity=v.severity,
        cvss=v.score,
        epss=v.epss,
        in_kev=v.kev,
        references=list(v.references),
        sources=[hit],
    )
    if locked is not None and locked != v.version and not is_affected(locked, finding):
        finding.fixed_in_source = True
    return finding


def load_import(path: Path, lock: dict[str, str]) -> ImportedFile:
    """Parse one Trivy / Wiz JSON file and map it onto the lockfile ``lock``."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ImportFileError(f"cannot read import file {path}: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise ImportFileError(f"import file {path} is not valid JSON") from exc
    try:
        tool, kind = detect_format(data)
    except ImportFileError as exc:
        raise ImportFileError(f"{path}: {exc}") from exc

    warnings: list[str] = []
    if tool == "trivy":
        tool_version = _trivy_version(data)
        vulns = _trivy_vulns(data)
        name = str(data.get("ArtifactName", "")) or path.name
        v = Version(tool_version) if tool_version else None
        if v is not None and _BAD_TRIVY[0] <= v <= _BAD_TRIVY[1]:
            warnings.append(
                f"{path.name} was made by Trivy {tool_version}, a compromised release; "
                "rescan with a safe Trivy version before trusting it"
            )
    else:
        tool_version = (data.get("extraInfo") or {}).get("clientVersion")
        vulns = _wiz_vulns(data)
        name = str((data.get("scanOriginResource") or {}).get("name", "")) or path.name

    target = f"image:{name}" if kind == "image" else "source"
    source = f"import:{path.name}"
    findings = [
        _to_finding(v, tool, tool_version, source, target, lock)
        for v in vulns
        if v.package and v.advisory
    ]
    return ImportedFile(path, tool, kind, target, tool_version, findings, warnings)
