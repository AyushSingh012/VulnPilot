"""Machine-readable scan output (the full RunReport writer comes with `fix`)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnpilot.scanner import ScanResult


def write_scan_json(result: ScanResult, path: Path) -> None:
    payload = {
        "run_id": result.run_id,
        "project": result.project.root.name,
        "manager": result.project.manager,
        "commit_sha": result.project.commit_sha,
        "tool_versions": result.tool_versions,
        "findings": [f.model_dump(mode="json") for f in result.shown],
        "ignored": [
            {"finding_key": f.key, "rule": r.id, "reason": r.reason} for f, r in result.ignored
        ],
        "below_threshold": [f.key for f in result.below_threshold],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
