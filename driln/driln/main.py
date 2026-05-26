"""FastAPI application factory.

Creates and configures the FastAPI app with:
- Lifespan handler for DB init and tool registry setup
- CORS middleware
- Exception handlers
- API router mounting
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from driln import __version__
from driln.core.exceptions import DrilnError
from driln.core.logging import setup_logging

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown hooks."""
    # ── Startup ──────────────────────────────────────────────
    setup_logging()
    logger.info("driln_starting", version=__version__)

    # Initialize database
    from driln.db.engine import close_db, init_db

    await init_db()
    logger.info("database_initialized")

    # Initialize tool registry
    from driln.tools.registry import init_registry

    registry = init_registry()

    # Ensure output directory exists
    from driln.core.config import get_settings

    settings = get_settings()
    settings.scan_output_dir.mkdir(parents=True, exist_ok=True)

    yield

    # ── Shutdown ─────────────────────────────────────────────
    await close_db()
    logger.info("driln_shutdown")


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title="Driln",
        description="Intelligent automated pentesting engine",
        version=__version__,
        lifespan=lifespan,
    )

    # ── CORS ─────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Exception handlers ───────────────────────────────────
    @app.exception_handler(DrilnError)
    async def driln_error_handler(request: Request, exc: DrilnError):
        return JSONResponse(
            status_code=400,
            content={
                "error": type(exc).__name__,
                "detail": exc.detail,
            },
        )

    # ── Routers ──────────────────────────────────────────────
    from driln.api.health import router as health_router
    from driln.api.v1.router import router as v1_router

    app.include_router(health_router)
    app.include_router(v1_router, prefix="/api/v1")

    return app


# Module-level app instance for uvicorn
app = create_app()
