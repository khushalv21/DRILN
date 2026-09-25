"""Output path utilities — human-readable scan output naming."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


def sanitize_target(target: str) -> str:
    """Sanitize a target string for use in file/directory names.

    Replaces special characters with hyphens, strips leading/trailing
    hyphens, and collapses consecutive hyphens.

    Examples:
        ``scanme.nmap.org`` → ``scanme.nmap.org``
        ``https://example.com:8080/path`` → ``example.com-8080``
        ``192.168.1.1`` → ``192.168.1.1``
    """
    # Strip protocol if present
    target = re.sub(r"^https?://", "", target)
    # Strip path
    target = target.split("/")[0]
    # Replace unsafe filesystem chars with hyphens
    target = re.sub(r"[^a-zA-Z0-9.\-_]", "-", target)
    # Collapse multiple hyphens
    target = re.sub(r"-+", "-", target)
    # Strip leading/trailing hyphens
    return target.strip("-")


def make_output_dir(base_dir: Path, target: str, timestamp: datetime | None = None) -> Path:
    """Build a human-readable output directory path.

    Format: ``{base_dir}/{target}_{YYYY-MM-DD_HH-MM}/``

    Args:
        base_dir: The root output directory (e.g., ``./output``).
        target: The scan target (domain, IP, etc.).
        timestamp: When the scan started. Defaults to now (UTC).

    Returns:
        Path to the output directory (not yet created).
    """
    ts = timestamp or datetime.now(UTC)
    safe_target = sanitize_target(target)
    dirname = f"{safe_target}_{ts.strftime('%Y-%m-%d_%H-%M')}"
    return base_dir / dirname


def make_report_filename(target: str, fmt: str = "markdown") -> str:
    """Build a human-readable report filename.

    Format: ``{target}_report.{ext}``

    Args:
        target: The scan target.
        fmt: Report format (``markdown`` or ``html``).

    Returns:
        Filename string like ``scanme.nmap.org_report.md``.
    """
    safe_target = sanitize_target(target)
    ext = "md" if fmt == "markdown" else "html"
    return f"{safe_target}_report.{ext}"
