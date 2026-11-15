"""VulnPilot: scan -> prioritize -> fix -> test -> rescan -> one PR."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vulnpilot")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0"
