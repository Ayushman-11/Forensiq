"""
API v1 Router Aggregator.
"""

from fastapi import APIRouter, Depends
from app.api.v1.endpoints import alerts, health, search, dashboard, auth
from app.api.deps import get_current_user

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(
    alerts.router, prefix="/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    search.router, prefix="/search", tags=["search"], dependencies=[Depends(get_current_user)]
)
api_router.include_router(
    dashboard.router, prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_user)]
)
