"""Async subprocess executor.

Provides a single function :func:`execute_subprocess` that runs a command
via ``asyncio.create_subprocess_exec``, captures stdout/stderr, and enforces
a timeout.  A module-level :class:`asyncio.Semaphore` limits concurrency.
"""

from __future__ import annotations

import asyncio

import structlog

from driln.core.config import get_settings

logger = structlog.get_logger()

# Lazy-initialized semaphore (must be created inside a running event loop)
_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        settings = get_settings()
        _semaphore = asyncio.Semaphore(settings.scan_max_concurrent)
    return _semaphore


async def execute_subprocess(
    cmd: list[str],
    *,
    timeout: int = 300,
    stdin_data: bytes | None = None,
) -> tuple[str, str, int]:
    """Run a command asynchronously and return ``(stdout, stderr, exit_code)``.

    Args:
        cmd: Command and arguments as a list of strings.
        timeout: Maximum execution time in seconds.
        stdin_data: Optional data to feed to the process stdin.

    Returns:
        Tuple of ``(stdout, stderr, return_code)``.

    Raises:
        TimeoutError: If the process exceeds *timeout* seconds.
    """
    sem = _get_semaphore()

    async with sem:
        logger.debug("subprocess_start", cmd=cmd[0], args=cmd[1:])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(input=stdin_data),
                timeout=timeout,
            )
        except TimeoutError:
            # Kill the process on timeout
            try:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                pass
            raise TimeoutError(f"Process timed out after {timeout}s: {cmd[0]}")

        stdout_raw = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr_raw = stderr_bytes.decode("utf-8", errors="replace").strip()

        # Cap output size to prevent memory exhaustion (10 MB)
        max_output = 10 * 1024 * 1024
        stdout = stdout_raw[:max_output]
        stderr = stderr_raw[:max_output]
        exit_code = process.returncode or 0

        logger.debug(
            "subprocess_done",
            cmd=cmd[0],
            exit_code=exit_code,
            stdout_len=len(stdout),
            stderr_len=len(stderr),
        )

        return stdout, stderr, exit_code
