"""Tool info endpoints — list and check tool availability."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from driln.api.deps import get_tool_registry
from driln.schemas.tools import ToolCheckResult, ToolInfo
from driln.tools.registry import ToolRegistry

router = APIRouter()


@router.get("", response_model=list[ToolInfo])
async def list_tools(
    registry: ToolRegistry = Depends(get_tool_registry),
):
    """List all registered tools with installation status."""
    results = await registry.check_all()
    return [
        ToolInfo(
            name=info["name"],
            description=info["description"],
            binary=info["binary"],
            installed=info["installed"],
        )
        for info in results.values()
    ]


@router.get("/{tool_name}/check", response_model=ToolCheckResult)
async def check_tool(
    tool_name: str,
    registry: ToolRegistry = Depends(get_tool_registry),
):
    """Check if a specific tool is installed and available."""
    try:
        tool = registry.get(tool_name)
    except Exception:
        return ToolCheckResult(
            name=tool_name,
            installed=False,
            error=f"Tool '{tool_name}' is not registered",
        )

    installed, path = await tool.check_installed()
    return ToolCheckResult(
        name=tool_name,
        installed=installed,
        path=path,
    )
