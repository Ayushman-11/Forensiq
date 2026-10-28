"""
API v1 Router Aggregator.
Wires endpoint routers with authentication, role gates, and rate limiting.
"""

from fastapi import APIRouter, Depends
from app.api.v1.endpoints import admin, alerts, health, search, dashboard, auth, reports, investigation_ws, users
from app.api.deps import get_current_user
from app.services.rate_limiter import rate_limiter
from app.core.config import settings

api_router = APIRouter(prefix="/api/v1")

# --- Rate-limit dependencies for expensive endpoints ---
_search_rate_limit = rate_limiter(
    max_requests=settings.RATE_LIMIT_SEARCH_MAX,
    window_seconds=settings.RATE_LIMIT_SEARCH_WINDOW,
    scope="search",
)
_investigate_rate_limit = rate_limiter(
    max_requests=settings.RATE_LIMIT_INVESTIGATE_MAX,
    window_seconds=settings.RATE_LIMIT_INVESTIGATE_WINDOW,
    scope="investigate",
)
_report_rate_limit = rate_limiter(
    max_requests=settings.RATE_LIMIT_REPORT_MAX,
    window_seconds=settings.RATE_LIMIT_REPORT_WINDOW,
    scope="report",
)

# --- Public / unauthenticated routes ---
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

# --- Admin routes (role-gated inside the router) ---
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])

# --- WebSocket route (authenticates via ticket/subprotocol internally) ---
api_router.include_router(
    investigation_ws.router, prefix="/alerts", tags=["websocket"]
)

# --- Authenticated + rate-limited routes ---
api_router.include_router(
    alerts.router,
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(get_current_user), Depends(_investigate_rate_limit)],
)
api_router.include_router(
    search.router,
    prefix="/search",
    tags=["search"],
    dependencies=[Depends(get_current_user), Depends(_search_rate_limit)],
)
api_router.include_router(
    dashboard.router,
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(get_current_user)],
)
api_router.include_router(
    reports.router,
    prefix="/alerts",
    tags=["reports"],
    dependencies=[Depends(get_current_user), Depends(_report_rate_limit)],
)
api_router.include_router(
    users.router, prefix="/users", tags=["users"], dependencies=[Depends(get_current_user)]
)
