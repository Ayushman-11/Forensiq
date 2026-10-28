"""
Forensiq FastAPI Main Application Entrypoint.
Configures app lifespan, middleware (security headers, body limits, CORS, trusted hosts), routers.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.errors import new_request_id
from app.core.logging import setup_logging, logger
from app.core.headers import SecurityHeadersMiddleware, RequestBodyLimitMiddleware
from app.api.v1.router import api_router
from app.database.indexes import ensure_indexes
from app.normalization.noise import NoiseFilter
from app.core.startup_checks import missing_integrations

from app.database.session import connect_to_mongo, close_mongo_connection
from app.services.poller import AlertPoller
from app.services.investigation_worker import InvestigationWorker
from app.services.job_queue import reap_stuck_jobs
from app.database.session import db_config

_NON_PROD_ENVS = frozenset({"development", "dev", "test", "testing", "local"})

poller = None
investigation_worker = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager handling startup and shutdown events."""
    setup_logging()
    logger.info("forensiq_backend_startup", env=settings.ENV, debug=settings.DEBUG)
    missing = missing_integrations(settings)
    if "threat_intel" in missing:
        logger.warning(
            "threat_intel_not_configured",
            missing=missing["threat_intel"],
            message="IOC enrichment returns no verdict from these feeds until their keys are set",
        )
    if "llm" in missing:
        logger.warning(
            "llm_not_configured",
            missing=missing["llm"],
            message="risk and recommendation agents will use deterministic rules",
        )
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

        try:
            await reap_stuck_jobs(db)
        except Exception as exc:
            logger.error("reap_stuck_jobs_failed", error=str(exc))

    global poller, investigation_worker
    if db_config.client:
        db = db_config.client[settings.MONGO_DB_NAME]
        try:
            investigation_worker = InvestigationWorker(db, poll_interval=settings.INVESTIGATION_WORKER_POLL_INTERVAL_SECONDS)
            investigation_worker.start()
        except Exception as exc:
            logger.error("investigation_worker_start_failed", error=str(exc))

        poller = AlertPoller(db, interval_seconds=settings.POLLER_INTERVAL_SECONDS)
        poller.start()

    yield
    
    if investigation_worker:
        try:
            await investigation_worker.stop()
        except Exception as exc:
            logger.error("investigation_worker_stop_failed", error=str(exc))
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

# --- Security Headers Middleware (outermost: runs on every response) ---
app.add_middleware(SecurityHeadersMiddleware)

# --- Request Body Size Limit Middleware ---
app.add_middleware(RequestBodyLimitMiddleware)

# --- Trusted Host Middleware (production only) ---
is_prod = settings.ENV.strip().lower() not in _NON_PROD_ENVS
if is_prod and settings.TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)

# --- CORS Middleware (tightened: explicit methods and headers) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Request-ID",
        "X-Requested-With",
    ],
    expose_headers=["X-Request-ID", "Retry-After"],
    max_age=600,
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
    }
