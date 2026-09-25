"""Scan-to-scan finding diff.

Compares the findings of a scan against the most recent prior *completed*
scan of the same target, to answer the question that matters most for
repeated engagements: what's new, what got fixed, and what's still there.

Matching two findings across scans uses the same host+port+title-similarity
approach as :mod:`driln.intelligence.dedup`, since exact title matching
would miss minor wording differences between tool runs (e.g. a nuclei
template version bump).
"""

from __future__ import annotations

from collections.abc import Sequence
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

from driln.db.models import Finding
from driln.db.repos import FindingRepository, ScanRepository
from driln.schemas.diff import ScanDiff
from driln.schemas.findings import FindingOut

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_TITLE_SIMILARITY_THRESHOLD = 0.75


def _title_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _is_match(previous: Finding, current: Finding) -> bool:
    if (previous.host or "") != (current.host or ""):
        return False
    if previous.port != current.port:
        return False
    return _title_similarity(previous.title, current.title) >= _TITLE_SIMILARITY_THRESHOLD


def diff_findings(
    previous: Sequence[Finding],
    current: Sequence[Finding],
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Compare two scans' findings.

    Args:
        previous: Findings from the earlier scan.
        current: Findings from the later scan.

    Returns:
        Tuple of ``(new_findings, fixed_findings, persisted_findings)``:

        * ``new_findings`` — present in *current* with no match in *previous*.
        * ``fixed_findings`` — present in *previous* with no match in *current*.
        * ``persisted_findings`` — matched in both (the *current* copy is kept).
    """
    matched_previous_idx: set[int] = set()
    matched_current_idx: set[int] = set()

    for ci, c in enumerate(current):
        for pi, p in enumerate(previous):
            if pi in matched_previous_idx:
                continue
            if _is_match(p, c):
                matched_previous_idx.add(pi)
                matched_current_idx.add(ci)
                break

    new_findings = [c for ci, c in enumerate(current) if ci not in matched_current_idx]
    fixed_findings = [p for pi, p in enumerate(previous) if pi not in matched_previous_idx]
    persisted_findings = [c for ci, c in enumerate(current) if ci in matched_current_idx]

    return new_findings, fixed_findings, persisted_findings


async def compute_scan_diff(session: AsyncSession, scan_id: str) -> ScanDiff | None:
    """Build a :class:`ScanDiff` for *scan_id* against its most recent prior
    completed scan of the same target.

    Returns:
        ``None`` if *scan_id* doesn't exist. If it exists but there's no
        prior completed scan of the same target, all current findings are
        reported as "new" and ``previous_scan_id`` is ``None``.
    """
    scan_repo = ScanRepository(session)
    finding_repo = FindingRepository(session)

    scan = await scan_repo.get(scan_id)
    if scan is None:
        return None

    current = await finding_repo.list_by_scan(scan_id)
    previous_scan = await scan_repo.get_previous_completed(scan.target, exclude_scan_id=scan_id)

    if previous_scan is None:
        return ScanDiff(
            scan_id=scan_id,
            target=scan.target,
            previous_scan_id=None,
            new_findings=[FindingOut.model_validate(f) for f in current],
            fixed_findings=[],
            persisted_findings=[],
        )

    previous = await finding_repo.list_by_scan(previous_scan.id)
    new, fixed, persisted = diff_findings(previous, current)

    return ScanDiff(
        scan_id=scan_id,
        target=scan.target,
        previous_scan_id=previous_scan.id,
        new_findings=[FindingOut.model_validate(f) for f in new],
        fixed_findings=[FindingOut.model_validate(f) for f in fixed],
        persisted_findings=[FindingOut.model_validate(f) for f in persisted],
    )
