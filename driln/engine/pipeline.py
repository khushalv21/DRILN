"""Scan pipelines — predefined tool sequences for common scan types.

Each pipeline defines an ordered list of tools to execute.  The scan engine
uses these to determine which tools to run and in what order.

Pipelines can be overridden per-scan via the ``tools`` field in
:class:`~driln.schemas.scans.ScanCreate`.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Pipeline Definitions ────────────────────────────────────────

PIPELINES: dict[str, list[str]] = {
    "recon": ["subfinder", "httpx", "nmap"],
    "vuln": ["nmap", "nuclei"],
    "full": ["subfinder", "httpx", "nmap", "nuclei"],
}


@dataclass
class PipelineStage:
    """A single stage in a pipeline.

    Attributes:
        tool_name: Name of the tool to run.
        depends_on: Optional list of tools whose output this stage needs.
        options_override: Per-stage option overrides.
    """

    tool_name: str
    depends_on: list[str] | None = None
    options_override: dict | None = None


def get_pipeline(scan_type: str) -> list[str]:
    """Return the tool list for a scan type.

    Args:
        scan_type: One of ``recon``, ``vuln``, ``full``.

    Returns:
        Ordered list of tool names.

    Raises:
        ValueError: If the scan type is unknown.
    """
    pipeline = PIPELINES.get(scan_type)
    if pipeline is None:
        available = ", ".join(PIPELINES.keys())
        raise ValueError(f"Unknown scan type '{scan_type}'. Available: {available}")
    return list(pipeline)  # Return a copy


def list_pipelines() -> dict[str, list[str]]:
    """Return all available pipelines."""
    return dict(PIPELINES)
