from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Analyst Copilot service")
    yield
    logger.info("Shutting down Analyst Copilot service")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Analyst Copilot - RAG-powered Threat Analysis",
        description="AI-powered investigation assistant for SOC analysts",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    from app.api.routers import copilot, health

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(copilot.router, prefix="/api/v1/copilot", tags=["copilot"])

    return app


app = create_app()
