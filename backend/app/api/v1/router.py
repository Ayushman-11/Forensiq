"""
API v1 Router Aggregator.
"""

from fastapi import APIRouter, Depends
from app.api.v1.endpoints import alerts, health, search, dashboard, auth, reports, investigation_ws, users
from app.api.deps import get_current_user

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
# WebSocket router mounted without HTTPBearer header dependency to allow browser WS token query param
api_router.include_router(
    investigation_ws.router, prefix="/alerts", tags=["websocket"]
)
api_router.include_router(
    alerts.router, prefix="/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    search.router, prefix="/search", tags=["search"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    dashboard.router, prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    reports.router, prefix="/alerts", tags=["reports"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    users.router, prefix="/users", tags=["users"], dependencies=[Depends(get_current_user)]
)
