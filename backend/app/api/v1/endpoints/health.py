"""
Health check endpoints.

Two separate probes following the Kubernetes split-probe convention:

  GET /api/v1/health/live   – liveness:  returns 200 as long as the process is
                               alive and not deadlocked.  Does NOT touch any
                               external dependency so a slow DB never makes the
                               pod restart-loop.

  GET /api/v1/health/ready  – readiness: returns 200 only when the application
                               can actually serve traffic (MongoDB reachable).
                               The SIEM / Splunk connection is intentionally
                               excluded here – SIEM state belongs on the SOC
                               dashboard, not in the readiness probe.
"""

import time

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.config import settings
from app.database.session import db_config

router = APIRouter()

_START_TIME = time.monotonic()


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class LivenessResponse(BaseModel):
    status: str
    uptime_seconds: float
    version: str = "0.1.0"


class ReadinessResponse(BaseModel):
    status: str
    mongo: str
    version: str = "0.1.0"


# ---------------------------------------------------------------------------
# Liveness probe  – /api/v1/health/live
# ---------------------------------------------------------------------------


@router.get(
    "/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description=(
        "Returns 200 if the process is alive. "
        "No external I/O – safe to poll frequently."
    ),
    tags=["health"],
)
async def liveness() -> LivenessResponse:
    """Always returns 200 while the process is running."""
    return LivenessResponse(
        status="alive",
        uptime_seconds=round(time.monotonic() - _START_TIME, 1),
    )


# ---------------------------------------------------------------------------
# Readiness probe  – /api/v1/health/ready
# ---------------------------------------------------------------------------


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "Returns 200 when the application is ready to serve traffic "
        "(MongoDB is reachable). "
        "Returns 503 if any critical dependency is unavailable."
    ),
    tags=["health"],
)
async def readiness() -> JSONResponse:
    """
    Checks only the dependencies that must be healthy for the API to work:
      - MongoDB connectivity (ping command)

    SIEM (Splunk) connectivity is intentionally excluded: a Splunk outage
    should surface on the SOC dashboard, not cause the API to be marked
    unready and drop all traffic.
    """
    checks: dict[str, str] = {}
    healthy = True

    # --- MongoDB ---
    if db_config.client is None:
        checks["mongo"] = "not_initialized"
        healthy = False
    else:
        try:
            # server_info() sends a lightweight ping to the primary.
            await db_config.client[settings.MONGO_DB_NAME].command("ping")
            checks["mongo"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["mongo"] = f"error: {type(exc).__name__}"
            healthy = False

    body = {
        "status": "ready" if healthy else "not_ready",
        "version": "0.1.0",
        **checks,
    }
    http_status = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=body, status_code=http_status)


# ---------------------------------------------------------------------------
# Legacy root – /api/v1/health  (kept for backwards compatibility)
# ---------------------------------------------------------------------------


@router.get(
    "",
    summary="Health (legacy)",
    description=(
        "Backwards-compatible combined health check. "
        "Prefer /live or /ready for new integrations."
    ),
    tags=["health"],
    deprecated=True,
)
async def health_legacy() -> JSONResponse:
    """
    Thin wrapper that delegates to the readiness check so existing callers
    keep working while we migrate them to the split probes.
    """
    return await readiness()
