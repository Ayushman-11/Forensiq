"""
Forensiq FastAPI Main Application Entrypoint.
Configures app lifespan, middleware, routers, and CORS.
"""

import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import new_request_id
from app.core.logging import logger, setup_logging
from app.database.indexes import ensure_indexes
from app.database.session import close_mongo_connection, connect_to_mongo, db_config
from app.normalization.noise import NoiseFilter
from app.services.poller import AlertPoller

poller = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager handling startup and shutdown events."""
    setup_logging()
    logger.info("forensiq_backend_startup", env=settings.ENV, debug=settings.DEBUG)
    # Fail fast on a broken noise policy instead of failing every ingestion cycle.
    NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH)
    await connect_to_mongo()

    if db_config.client:
        db = db_config.client[settings.MONGO_DB_NAME]
        # TTL index: let MongoDB itself expire session documents once their
        # expires_at timestamp has passed, instead of relying solely on the
        # refresh JWT's own exp claim (which the session store never enforces).
        await db["sessions"].create_index(
            "expires_at", expireAfterSeconds=0
        )
        # Compound index and TTL index for IOC threat intelligence cache
        await db["ioc_cache"].create_index([("ioc", 1), ("source", 1)], unique=True)
        await db["ioc_cache"].create_index(
            "cached_at", expireAfterSeconds=int(settings.IOC_CACHE_TTL_HOURS * 3600)
        )
        try:
            await ensure_indexes(db)
        except Exception as exc:  # e.g. a conflicting pre-existing index must not take the API down
            logger.error("ensure_indexes_failed", error=str(exc))

    global poller
    if db_config.client:
        poller = AlertPoller(db_config.client[settings.MONGO_DB_NAME], interval_seconds=30)
        poller.start()

    yield

    if poller:
        await poller.stop()

    await close_mongo_connection()
    logger.info("forensiq_backend_shutdown")


app = FastAPI(
    title="Forensiq API",
    description="AI-Agent Driven Security Operations & Investigation Platform API",
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Prometheus instrumentation
# Exposes GET /metrics (Prometheus text format).
# Must be created before routers are included so it can instrument all routes.
# ---------------------------------------------------------------------------
Instrumentator(
    should_group_status_codes=True,
    should_ignore_untemplated=True,
    should_respect_env_var=False,
    should_instrument_requests_inprogress=True,
    inprogress_labels=True,
    excluded_handlers=["/metrics"],
).instrument(app).expose(app, include_in_schema=False, tags=["observability"])


# ---------------------------------------------------------------------------
# Request-ID middleware
# Stamps every request with a unique ID so logs and responses can be correlated.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or new_request_id()
    # Bind the request id into the structlog context for this coroutine.
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=req_id, path=request.url.path)
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = round((time.monotonic() - start) * 1000, 1)
    logger.info(
        "http_request",
        method=request.method,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    response.headers["X-Request-ID"] = req_id
    return response


# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global unhandled exception handler: generic body, real error logged under a request id."""
    ref = new_request_id()
    logger.error(
        "unhandled_exception", path=request.url.path, request_id=ref,
        error=str(exc), error_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred.", "request_id": ref},
        headers={"X-Request-ID": ref},
    )


# Include API Routers
app.include_router(api_router)


@app.get("/")
async def root():
    """Root landing endpoint."""
    return {
        "platform": "Forensiq Security Operations Platform",
        "status": "operational",
        "docs": "/docs",
        "api_v1": "/api/v1",
        "metrics": "/metrics",
    }
