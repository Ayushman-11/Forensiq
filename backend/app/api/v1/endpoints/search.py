"""
Search API endpoints for querying normalized telemetry across SIEM providers.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from app.api.deps import get_siem_client
from app.infrastructure.siem.base import SIEMProvider
from app.schemas.normalized_event import NormalizedEvent

router = APIRouter()


class SearchRequest(BaseModel):
    query: str = Field(..., description="SPL query or keyword search string", json_schema_extra={"example": 'source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1'})
    earliest_time: str = Field(default="-24h", description="Earliest time bounds")
    latest_time: str = Field(default="now", description="Latest time bounds")
    limit: int = Field(default=50, ge=1, le=1000, description="Max results limit")


class SearchResponse(BaseModel):
    count: int
    query: str
    events: List[NormalizedEvent]


@router.post("/search", response_model=SearchResponse)
async def execute_search(
    req: SearchRequest,
    siem: SIEMProvider = Depends(get_siem_client),
):
    """
    Executes a search query against the configured SIEM provider and returns normalized events.
    No raw SIEM payloads exposed in API contract.
    """
    try:
        events = await siem.search(
            query=req.query,
            earliest_time=req.earliest_time,
            latest_time=req.latest_time,
            limit=req.limit,
        )
        return SearchResponse(count=len(events), query=req.query, events=events)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SIEM Search Error: {str(e)}",
        )
