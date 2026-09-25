"""Health check endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from driln import __version__

router = APIRouter(tags=["health"])


@router.get("/health", response_model=dict)
async def health_check() -> dict[str, Any]:
    """Application health check."""
    return {
        "status": "healthy",
        "version": __version__,
        "service": "driln",
    }
