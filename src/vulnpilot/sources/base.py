from __future__ import annotations

from typing import Protocol

from vulnpilot.models import Finding, Project


class SourceError(Exception):
    """A scanner failed or produced output VulnPilot cannot read."""


class Source(Protocol):
    """OsvSource now; ImportedFile (Trivy / Wiz JSON) in Stage 5."""

    name: str

    def collect(self, project: Project) -> list[Finding]: ...
