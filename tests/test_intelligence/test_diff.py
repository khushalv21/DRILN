"""Tests for scan-to-scan finding diffing."""

from __future__ import annotations

import pytest

from driln.db.models import Finding, ScanStatus, Severity
from driln.db.repos import FindingRepository, ScanRepository
from driln.intelligence.diff import compute_scan_diff, diff_findings


def _finding(**overrides) -> Finding:
    defaults = dict(
        scan_id="s1",
        severity=Severity.HIGH,
        title="Outdated nginx version",
        host="example.com",
        port=443,
        service="https",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_diff_findings_detects_new_and_fixed():
    previous = [
        _finding(title="Outdated nginx version"),
        _finding(title="Exposed .git directory", port=80),
    ]
    current = [
        _finding(title="Outdated nginx version"),  # unchanged
        _finding(title="Weak TLS cipher suite", port=443),  # new
    ]

    new, fixed, persisted = diff_findings(previous, current)

    assert [f.title for f in new] == ["Weak TLS cipher suite"]
    assert [f.title for f in fixed] == ["Exposed .git directory"]
    assert [f.title for f in persisted] == ["Outdated nginx version"]


def test_diff_findings_matches_similar_titles_same_host_port():
    """Minor wording differences (e.g. a template version bump) shouldn't
    register as new+fixed instead of persisted."""
    previous = [_finding(title="nginx version disclosure detected")]
    current = [_finding(title="nginx version disclosure found")]

    new, fixed, persisted = diff_findings(previous, current)

    assert new == []
    assert fixed == []
    assert len(persisted) == 1


def test_diff_findings_does_not_match_across_different_ports():
    previous = [_finding(port=80)]
    current = [_finding(port=443)]

    new, fixed, persisted = diff_findings(previous, current)

    assert len(new) == 1
    assert len(fixed) == 1
    assert persisted == []


def test_diff_findings_empty_inputs():
    assert diff_findings([], []) == ([], [], [])
    only_current = [_finding()]
    assert diff_findings([], only_current) == (only_current, [], [])
    only_previous = [_finding()]
    assert diff_findings(only_previous, []) == ([], only_previous, [])


@pytest.mark.asyncio
async def test_compute_scan_diff_no_previous_scan(db_session):
    scan_repo = ScanRepository(db_session)
    finding_repo = FindingRepository(db_session)

    scan = await scan_repo.create(target="example.com", scan_type="full")
    await scan_repo.update_status(scan.id, ScanStatus.COMPLETED)
    await finding_repo.bulk_create(
        [{"scan_id": scan.id, "title": "Open port 22", "severity": "low", "host": "example.com"}]
    )
    await db_session.commit()

    diff = await compute_scan_diff(db_session, scan.id)

    assert diff is not None
    assert diff.previous_scan_id is None
    assert len(diff.new_findings) == 1
    assert diff.fixed_findings == []
    assert diff.persisted_findings == []


@pytest.mark.asyncio
async def test_compute_scan_diff_with_previous_scan(db_session):
    scan_repo = ScanRepository(db_session)
    finding_repo = FindingRepository(db_session)

    old_scan = await scan_repo.create(target="example.com", scan_type="full")
    await finding_repo.bulk_create(
        [
            {
                "scan_id": old_scan.id,
                "title": "Open port 22",
                "severity": "low",
                "host": "example.com",
                "port": 22,
            },
            {
                "scan_id": old_scan.id,
                "title": "Outdated Apache",
                "severity": "medium",
                "host": "example.com",
                "port": 80,
            },
        ]
    )
    await scan_repo.update_status(old_scan.id, ScanStatus.COMPLETED)

    new_scan = await scan_repo.create(target="example.com", scan_type="full")
    await finding_repo.bulk_create(
        [
            {
                "scan_id": new_scan.id,
                "title": "Open port 22",
                "severity": "low",
                "host": "example.com",
                "port": 22,
            },
            {
                "scan_id": new_scan.id,
                "title": "Exposed Redis",
                "severity": "critical",
                "host": "example.com",
                "port": 6379,
            },
        ]
    )
    await scan_repo.update_status(new_scan.id, ScanStatus.COMPLETED)
    await db_session.commit()

    diff = await compute_scan_diff(db_session, new_scan.id)

    assert diff is not None
    assert diff.previous_scan_id == old_scan.id
    assert [f.title for f in diff.new_findings] == ["Exposed Redis"]
    assert [f.title for f in diff.fixed_findings] == ["Outdated Apache"]
    assert [f.title for f in diff.persisted_findings] == ["Open port 22"]


@pytest.mark.asyncio
async def test_compute_scan_diff_unknown_scan_returns_none(db_session):
    diff = await compute_scan_diff(db_session, "does-not-exist")
    assert diff is None
