"""Keep only the parts of a wizcli JSON report that VulnPilot's tests need.

Usage:  uv run python scripts/scrub_wiz.py <raw.json> <out.json>

An allow-list, not a deny-list: scan / service-account / finding ids, the report URL,
policy names and ignore rules (all specific to a Wiz tenant) are dropped by construction.
A policy hit is kept only as a count, under a neutral name.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_VULN_KEYS = (
    "name", "severity", "fixedVersion", "source", "score", "hasExploit",
    "hasCisaKevExploit", "epssProbability", "epssPercentile", "epssSeverity",
)  # fmt: skip
_PKG_KEYS = ("name", "version", "path", "detectionMethod")
_SAMPLE_POLICY = {"policy": {"name": "Sample policy", "type": "VULNERABILITIES"}}


def _pick(obj: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: obj[k] for k in keys if k in obj}


def _vuln(v: dict[str, Any]) -> dict[str, Any]:
    out = _pick(v, _VULN_KEYS)
    if v.get("failedPolicyMatches"):
        out["failedPolicyMatches"] = [_SAMPLE_POLICY]
    return out


def _packages(items: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if items is None:
        return None
    return [
        {
            **_pick(p, _PKG_KEYS),
            "vulnerabilities": [_vuln(v) for v in p.get("vulnerabilities") or []],
        }
        for p in items
    ]


def scrub(raw: dict[str, Any]) -> dict[str, Any]:
    result = raw.get("result") or {}
    analytics = (result.get("analytics") or {}).get("vulnerabilities")
    origin = raw.get("scanOriginResource") or {}
    return {
        "createdAt": raw.get("createdAt"),
        "extraInfo": {
            "clientName": "WizCLI",
            "clientVersion": (raw.get("extraInfo") or {}).get("clientVersion"),
        },
        "scanOriginResource": _pick(origin, ("__typename", "name")),
        "status": _pick(raw.get("status") or {}, ("state", "verdict")),
        "result": {
            "osPackages": _packages(result.get("osPackages")),
            "libraries": _packages(result.get("libraries")),
            "cpes": _packages(result.get("cpes")),
            "secrets": [] if result.get("secrets") is not None else None,
            "analytics": {"vulnerabilities": analytics} if analytics else None,
        },
    }


if __name__ == "__main__":
    src, dest = Path(sys.argv[1]), Path(sys.argv[2])
    dest.write_text(json.dumps(scrub(json.loads(src.read_text("utf-8"))), indent=2) + "\n", "utf-8")
