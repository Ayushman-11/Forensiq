import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_siem_client, get_db, require_roles
from app.core.config import settings
from app.core.tenancy import scoped_query
from app.services.audit import record_audit
from app.services.spl_guard import SPLRejected, validate_search, validate_time_range
from app.infrastructure.siem.base import SIEMProvider
from app.schemas.normalized_event import NormalizedEvent
from app.core.logging import logger

router = APIRouter()


class SearchRequest(BaseModel):
    query: str = Field(..., max_length=4000, description="SPL query or keyword search string", json_schema_extra={"example": 'source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1'})
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
    user: dict = Depends(require_roles("admin", "soc_manager", "soc_analyst")),
):
    """
    Executes a guarded search against the configured SIEM and returns normalized events.
    If Splunk is unavailable, falls back to searching the caller's tenant data in MongoDB.
    """
    try:
        validate_time_range(req.earliest_time, req.latest_time, settings.SEARCH_MAX_RANGE_DAYS)
        safe_query = validate_search(
            req.query,
            allowed_indexes={*settings.SPLUNK_ALLOWED_INDEXES, settings.SPLUNK_DETECTION_INDEX},
            default_index=settings.SPLUNK_DETECTION_INDEX,
        )
    except SPLRejected as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    try:
        await record_audit(db, user, "search.execute", "search", "splunk", {"query": safe_query[:500]})
    except Exception as exc:  # auditing must not make search unavailable, but must be visible in logs
        logger.error("search_audit_failed", error=str(exc))

    try:
        events = await siem.search(
            query=safe_query,
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

        cursor = db["alerts"].find(scoped_query(user, mongo_query) if mongo_query else scoped_query(user)).limit(req.limit)
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

