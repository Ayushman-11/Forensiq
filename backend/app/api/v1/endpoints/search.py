import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_siem_client, get_db
from app.infrastructure.siem.base import SIEMProvider
from app.schemas.normalized_event import NormalizedEvent
from app.core.logging import logger

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


@router.post("", response_model=SearchResponse)
@router.post("/", response_model=SearchResponse)
async def execute_search(
    req: SearchRequest,
    siem: SIEMProvider = Depends(get_siem_client),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Executes a search query against the configured SIEM provider and returns normalized events.
    If Splunk is unavailable or unauthenticated, gracefully falls back to searching stored telemetry in MongoDB.
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
        logger.warning("siem_search_fallback_to_mongodb", error=str(e), query=req.query)

        # Extract search terms from query for MongoDB regex lookup
        raw_terms = re.findall(r'[a-zA-Z0-9_\-\.\:]+', req.query)
        stop_words = {"search", "index", "source", "sourcetype", "or", "and", "not", "where", "table", "stats", "by", "count"}
        search_terms = [t for t in raw_terms if t.lower() not in stop_words]

        mongo_query = {}
        if search_terms:
            regex_pattern = "|".join(re.escape(t) for t in search_terms[:5])
            mongo_query = {
                "$or": [
                    {"title": {"$regex": regex_pattern, "$options": "i"}},
                    {"description": {"$regex": regex_pattern, "$options": "i"}},
                    {"host": {"$regex": regex_pattern, "$options": "i"}},
                    {"user": {"$regex": regex_pattern, "$options": "i"}},
                    {"process_name": {"$regex": regex_pattern, "$options": "i"}},
                    {"command_line": {"$regex": regex_pattern, "$options": "i"}},
                    {"rule_name": {"$regex": regex_pattern, "$options": "i"}},
                    {"alert_type": {"$regex": regex_pattern, "$options": "i"}},
                ]
            }

        cursor = db["alerts"].find(mongo_query).limit(req.limit)
        alert_docs = await cursor.to_list(length=req.limit)

        events: List[NormalizedEvent] = []
        for doc in alert_docs:
            created_at = doc.get("created_at")
            if isinstance(created_at, dict) and "$date" in created_at:
                try:
                    ts = datetime.fromisoformat(created_at["$date"].replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            elif isinstance(created_at, datetime):
                ts = created_at
            else:
                ts = datetime.now(timezone.utc)

            events.append(
                NormalizedEvent(
                    timestamp=ts,
                    event_id=str(doc.get("event_code") or doc.get("_id", "0")),
                    provider=doc.get("source_siem", "MongoDB-Telemetry"),
                    hostname=str(doc.get("host") or doc.get("affected_hostname") or "unknown"),
                    user=doc.get("user") or doc.get("affected_user"),
                    domain=doc.get("domain"),
                    process_name=doc.get("process_name"),
                    command_line=doc.get("command_line"),
                    parent_process_name=doc.get("parent_process"),
                    source_ip=doc.get("source_ip"),
                    destination_ip=doc.get("dest_ip"),
                    destination_port=int(doc["dest_port"]) if doc.get("dest_port") and str(doc["dest_port"]).isdigit() else None,
                    severity=str(doc.get("severity", "informational")).lower(),
                    raw_payload=doc,
                )
            )

        return SearchResponse(count=len(events), query=req.query, events=events)

