"""
Health check endpoints for platform status and SIEM connectivity.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.api.deps import get_siem_client
from app.infrastructure.siem.base import SIEMProvider

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    siem_connected: bool
    version: str = "0.1.0"


@router.get("", response_model=HealthResponse)
async def health_check(siem: SIEMProvider = Depends(get_siem_client)):
    """Health check endpoint verifying system health and SIEM connection."""
    siem_ok = False
    try:
        siem_ok = await siem.authenticate()
    except Exception:
        siem_ok = False

    return HealthResponse(
        status="healthy" if siem_ok else "degraded",
        siem_connected=siem_ok,
    )
