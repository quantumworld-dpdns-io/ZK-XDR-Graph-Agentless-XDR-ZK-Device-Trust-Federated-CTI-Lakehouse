from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CTI Lakehouse service")
    yield
    logger.info("Shutting down CTI Lakehouse service")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CTI Lakehouse - Federated Threat Intelligence",
        description="Federated CTI IoC management and matching for ZK-XDR Graph",
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

    from app.api.routers import health, iocs

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(iocs.router, prefix="/api/v1/iocs", tags=["iocs"])

    return app


app = create_app()
