"""Tool registry — discover, register, and look up tool instances.

The registry is populated at startup based on ``Settings.tools_enabled``.
Tools that are not installed on the host are still registered but marked
as unavailable.
"""

from __future__ import annotations

import structlog

from driln.core.config import get_settings
from driln.core.exceptions import ToolNotFoundError
from driln.tools.base import BaseTool

logger = structlog.get_logger()

# ── Built-in tool classes (imported lazily to avoid circular deps) ───


def _load_builtin_tools() -> dict[str, type[BaseTool]]:
    """Import and return all built-in tool classes keyed by name."""
    from driln.tools.httpx_tool import HttpxTool
    from driln.tools.nmap import NmapTool
    from driln.tools.nuclei import NucleiTool
    from driln.tools.subfinder import SubfinderTool

    return {
        "nmap": NmapTool,
        "subfinder": SubfinderTool,
        "httpx": HttpxTool,
        "nuclei": NucleiTool,
    }


class ToolRegistry:
    """Central registry for pentesting tool instances."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance."""
        self._tools[tool.name] = tool
        logger.debug("tool_registered", tool=tool.name)

    def get(self, name: str) -> BaseTool:
        """Get a registered tool by name.

        Raises:
            ToolNotFoundError: If the tool is not registered.
        """
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFoundError(f"Tool '{name}' is not registered.")
        return tool

    def list_all(self) -> list[str]:
        """Return names of all registered tools."""
        return list(self._tools.keys())

    async def list_available(self) -> list[str]:
        """Return names of registered tools whose binaries are installed."""
        available = []
        for name, tool in self._tools.items():
            installed, _ = await tool.check_installed()
            if installed:
                available.append(name)
        return available

    async def check_all(self) -> dict[str, dict]:
        """Check installation status of all registered tools."""
        results = {}
        for name, tool in self._tools.items():
            installed, path = await tool.check_installed()
            results[name] = {
                "name": name,
                "description": tool.description,
                "binary": tool.binary,
                "installed": installed,
                "path": path,
            }
        return results


# ── Module-level singleton ──────────────────────────────────────

_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Return the global tool registry, creating it if needed."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def init_registry() -> ToolRegistry:
    """Populate the registry with built-in tools per settings."""
    settings = get_settings()
    registry = get_registry()
    builtins = _load_builtin_tools()

    for tool_name in settings.tools_enabled:
        tool_cls = builtins.get(tool_name)
        if tool_cls is None:
            logger.warning("tool_unknown", tool=tool_name)
            continue
        registry.register(tool_cls())

    logger.info("tool_registry_initialized", tools=registry.list_all())
    return registry
