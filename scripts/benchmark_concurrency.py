#!/usr/bin/env python3
"""Concurrency benchmark for ScanEngine.

Fires many scans at the engine simultaneously, using a fake tool that
returns synthetic findings instantly instead of shelling out to real
security tools. This isolates what the benchmark is actually meant to
measure: whether the async engine, the SQLite session factory, and the
intelligence pipeline hold up under concurrent load — not how fast
subfinder/nuclei/etc. run, which depends entirely on the network and
target.

Usage:
    PYTHONPATH=. python scripts/benchmark_concurrency.py --scans 500 --findings-per-scan 10

Results are specific to the machine it's run on; re-run it rather than
trusting a number pasted into a doc.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import tempfile
import time
from pathlib import Path


async def _run(num_scans: int, findings_per_scan: int) -> None:
    from driln.core.logging import setup_logging
    from driln.db.engine import _get_session_factory, close_db, init_db
    from driln.db.models import ScanStatus
    from driln.db.repos import FindingRepository, ScanRepository
    from driln.engine.scanner import ScanEngine
    from driln.tools.base import BaseTool, ToolResult
    from driln.tools.registry import get_registry

    class _FakeTool(BaseTool):
        name = "mock"
        description = "synthetic benchmark tool"
        binary = "mock"

        def build_command(self, target: str, options: dict[str, object]) -> list[str]:
            return ["mock", target]

        def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
            raise NotImplementedError

        async def check_installed(self) -> tuple[bool, str | None]:
            return True, "/usr/bin/mock"

        async def run(
            self, target: str, options: dict[str, object] | None = None, timeout: int = 300
        ) -> ToolResult:
            findings = [
                {
                    "severity": "medium",
                    "title": f"Synthetic finding {i}",
                    "host": target,
                    "port": 8000 + i,
                    "service": "http",
                }
                for i in range(findings_per_scan)
            ]
            return ToolResult(
                tool_name="mock",
                command=f"mock {target}",
                raw_output="{}",
                parsed_data={},
                findings=findings,
                exit_code=0,
                duration=0.0,
                success=True,
            )

    setup_logging()
    logging.getLogger().setLevel(logging.CRITICAL)
    get_registry().register(_FakeTool())
    await init_db()

    engine = ScanEngine()
    scan_ids = await asyncio.gather(
        *(
            engine.create_scan(target=f"target-{i}.example.com", scan_type="full", tools=["mock"])
            for i in range(num_scans)
        )
    )

    start = time.perf_counter()
    results = await asyncio.gather(*(engine.run_scan(sid) for sid in scan_ids), return_exceptions=True)
    elapsed = time.perf_counter() - start

    failures = [r for r in results if isinstance(r, Exception)]

    factory = _get_session_factory()
    async with factory() as session:
        scan_repo = ScanRepository(session)
        finding_repo = FindingRepository(session)
        completed = 0
        total_findings = 0
        for sid in scan_ids:
            scan = await scan_repo.get(sid)
            if scan is not None and scan.status == ScanStatus.COMPLETED:
                completed += 1
            findings = await finding_repo.list_by_scan(sid)
            total_findings += len(findings)

    await close_db()

    print(f"Scans requested:      {num_scans}")
    print(f"Scans completed:      {completed}/{num_scans}")
    print(f"Exceptions raised:    {len(failures)}")
    print(f"Findings persisted:   {total_findings} (expected {num_scans * findings_per_scan})")
    print(f"Wall clock time:      {elapsed:.2f}s")
    print(f"Success rate:         {completed / num_scans * 100:.1f}%")

    if failures:
        print("\nFirst exception:")
        raise failures[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scans", type=int, default=500, help="Number of concurrent scans")
    parser.add_argument("--findings-per-scan", type=int, default=10, help="Synthetic findings per scan")
    args = parser.parse_args()

    # Use an isolated temp SQLite DB so this never touches ./driln.db.
    # DRILN_DATABASE_URL must be set before any driln module reads settings.
    db_path = Path(tempfile.mkstemp(suffix=".db")[1])
    os.environ["DRILN_DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"

    try:
        asyncio.run(_run(args.scans, args.findings_per_scan))
    finally:
        db_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
