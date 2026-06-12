"""Base tool abstraction.

Every pentesting tool integration inherits from :class:`BaseTool` and
implements two methods:

* :meth:`build_command` — construct the CLI invocation.
* :meth:`parse_output` — convert raw stdout into a structured
  :class:`ToolResult`.

The base class provides :meth:`run` (async execution via the shared
subprocess executor) and :meth:`check_installed` for free.
"""

from __future__ import annotations

import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

from driln.core.exceptions import ToolExecutionError, ToolNotFoundError, ToolTimeoutError
from driln.tools.executor import execute_subprocess

logger = structlog.get_logger()


@dataclass
class ToolResult:
    """Structured output from a tool execution."""

    tool_name: str
    command: str
    raw_output: str
    parsed_data: dict[str, Any]
    findings: list[dict[str, Any]]
    exit_code: int
    duration: float
    success: bool
    error: str | None = None
    stderr: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def summary(self) -> dict[str, Any]:
        """Return a concise summary suitable for logging."""
        return {
            "tool": self.tool_name,
            "success": self.success,
            "exit_code": self.exit_code,
            "findings": self.finding_count,
            "duration": round(self.duration, 2),
        }


@dataclass
class ToolMeta:
    """Declarative metadata for a tool.  Subclasses set these as class
    attributes; the dataclass just provides type hints for documentation."""

    name: str = ""
    description: str = ""
    binary: str = ""
    version_flag: str = "--version"
    default_options: dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """Abstract base class for all pentesting tool integrations.

    Subclass contract:
        1. Set ``name``, ``description``, ``binary`` class attributes.
        2. Implement ``build_command(target, options) -> list[str]``.
        3. Implement ``parse_output(raw_output, exit_code) -> ToolResult``.
    """

    # ── Subclass must set these ──────────────────────────────────
    name: str = ""
    description: str = ""
    binary: str = ""
    version_flag: str = "--version"
    allowed_extra_args: frozenset[str] = frozenset()

    # ── Public API ───────────────────────────────────────────────

    @abstractmethod
    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Return the full command as a list of arguments.

        Example: ``["nmap", "-sV", "-sC", "-oX", "-", "example.com"]``
        """
        ...

    @abstractmethod
    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        """Parse raw stdout into a structured :class:`ToolResult`."""
        ...

    async def check_installed(self) -> tuple[bool, str | None]:
        """Check whether the tool binary exists in ``$PATH``.

        Returns:
            Tuple of ``(is_installed, binary_path_or_None)``.
        """
        path = shutil.which(self.binary)
        return (path is not None, path)

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Execute the tool end-to-end.

        1. Verify installation.
        2. Build the command.
        3. Run via async subprocess.
        4. Parse output.

        Raises:
            ToolNotFoundError: Binary not in PATH.
            ToolTimeoutError: Execution exceeded *timeout*.
            ToolExecutionError: Non-zero exit with no parsed output.
        """
        opts = options or {}

        # Validate extra_args to prevent argument injection
        extra_args = opts.get("extra_args", [])
        if extra_args:
            for arg in extra_args:
                if arg.startswith("-") and arg not in self.allowed_extra_args:
                    raise ToolExecutionError(
                        f"Disallowed extra argument '{arg}' for tool '{self.name}'. "
                        f"Allowed flags: {', '.join(self.allowed_extra_args) if self.allowed_extra_args else 'None'}"
                    )

        # 1. Check installation
        installed, path = await self.check_installed()
        if not installed:
            raise ToolNotFoundError(
                f"Tool '{self.name}' not found. Ensure '{self.binary}' is in PATH."
            )

        # 2. Build command
        cmd = self.build_command(target, opts)
        cmd_str = " ".join(cmd)

        logger.info("tool_starting", tool=self.name, target=target, command=cmd_str)
        start = time.monotonic()

        # 3. Execute
        try:
            stdout, stderr, exit_code = await execute_subprocess(cmd, timeout=timeout)
        except TimeoutError as exc:
            duration = time.monotonic() - start
            logger.warning("tool_timeout", tool=self.name, timeout=timeout, duration=duration)
            raise ToolTimeoutError(
                f"Tool '{self.name}' timed out after {timeout}s"
            ) from exc

        duration = time.monotonic() - start

        # 4. Parse
        try:
            result = self.parse_output(stdout, exit_code)
            result.command = cmd_str
            result.duration = duration
            result.stderr = stderr
        except Exception as exc:
            logger.error("tool_parse_error", tool=self.name, error=str(exc))
            raise ToolExecutionError(
                f"Failed to parse output from '{self.name}': {exc}"
            ) from exc

        logger.info("tool_completed", **result.summary())
        return result
