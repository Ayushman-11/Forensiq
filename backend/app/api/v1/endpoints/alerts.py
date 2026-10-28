"""
Alert Ingestion and Listing endpoints.
"""

from typing import List, Dict, Any, Literal, Optional
from datetime import datetime, timedelta, timezone
import re
import uuid
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import AlertModel
from app.services.ingestion import IngestionService
from app.agents.graph import investigation_graph
from app.core.logging import logger
from app.core.errors import internal_error, new_request_id
from app.api.deps import require_roles, get_current_user
from app.core.tenancy import scoped_query, tenant_filter, tenant_id
from app.services.audit import record_audit
from app.services.correlation import correlate_alert
from app.services.triage import (
    OPEN_STATUSES,
    TriageError,
    apply_disposition,
    assign_alert,
    sla_state,
)
from app.services.investigation_streamer import (
    investigation_stream_manager,
    finalize_and_save_investigation as _finalize_and_save_investigation,
    json_serial,
)

router = APIRouter()

class DispositionRequest(BaseModel):
    action: Literal["close", "escalate", "suppress", "reopen"]
    verdict: Optional[Literal["true_positive", "benign_true_positive", "false_positive", "duplicate"]] = None
    note: Optional[str] = Field(default=None, max_length=5000)


class AssignRequest(BaseModel):
    assignee_id: Optional[str] = Field(default=None, max_length=100)


class BulkRequest(BaseModel):
    alert_ids: List[str] = Field(min_length=1, max_length=200)
    action: Literal["assign", "close", "escalate", "suppress", "reopen"]
    verdict: Optional[Literal["true_positive", "benign_true_positive", "false_positive", "duplicate"]] = None
    note: Optional[str] = Field(default=None, max_length=5000)
    assignee_id: Optional[str] = Field(default=None, max_length=100)


SORTS = {
    "newest": [("_detected", -1)],
    "oldest": [("_detected", 1)],
    "severity": [("_sev_rank", -1), ("_detected", -1)],
    "risk": [("risk_score", -1), ("_detected", -1)],
}
SEVERITY_RANK = {"$switch": {"branches": [
    {"case": {"$eq": ["$severity", "critical"]}, "then": 4},
    {"case": {"$eq": ["$severity", "high"]}, "then": 3},
    {"case": {"$eq": ["$severity", "medium"]}, "then": 2},
    {"case": {"$eq": ["$severity", "low"]}, "then": 1},
], "default": 0}}


def _triage_error(exc: TriageError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)

class NoteRequest(BaseModel):
    content: str = Field(min_length=1, max_length=5000)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {
    s.lower(): s
    for s in ("New", "Investigating", "Investigated", "Investigation Failed", "Closed", "Escalated", "Suppressed")
}

@router.get("/", response_model=List[dict])
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: str = Query(None, description="Filter by severity"),
    status: str = Query(None, description="Filter by status"),
    search: str = Query(None, max_length=100, description="Search in title or host"),
    assignee: str = Query(None, max_length=100, description="'me', 'unassigned' or a user id"),
    sort: Literal["newest", "oldest", "severity", "risk"] = Query("newest"),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Fetches alerts with optional filtering. status=open means every not-yet-resolved status."""
    conditions = []
    if assignee == "me":
        conditions.append({"assignee_id": user.get("id")})
    elif assignee == "unassigned":
        conditions.append({"assignee_id": {"$in": [None]}})
    elif assignee:
        conditions.append({"assignee_id": assignee})
    if severity and severity.lower() != "all":
        if severity.lower() not in VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(VALID_SEVERITIES)} or 'all'")
        conditions.append({"severity": severity.lower()})
    if status and status.lower() == "open":
        conditions.append({"status": {"$in": list(OPEN_STATUSES)}})
    elif status and status.lower() != "all":
        canonical = VALID_STATUSES.get(status.lower())
        if canonical is None:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(VALID_STATUSES.values())}, 'open' or 'all'")
        conditions.append({"status": canonical})
    if search:
        pattern = re.escape(search)
        conditions.append({"$or": [
            {"title": {"$regex": pattern, "$options": "i"}},
            {"host": {"$regex": pattern, "$options": "i"}},
        ]})
    try:
        alerts = []
        pipeline = [
            {"$match": scoped_query(user, *conditions)},
            {"$addFields": {"_detected": {"$ifNull": ["$detected_at", "$created_at"]}, "_sev_rank": SEVERITY_RANK}},
            {"$sort": dict(SORTS[sort])},
            {"$limit": limit},
            {"$project": {"raw_events": 0, "_sev_rank": 0, "_detected": 0}},
        ]
        async for document in db["alerts"].aggregate(pipeline):
            document["_id"] = str(document["_id"])
            document["sla"] = sla_state(document)
            for key in ("created_at", "detected_at", "acknowledged_at", "resolved_at", "assigned_at", "updated_at"):
                if isinstance(document.get(key), datetime):
                    document[key] = document[key].isoformat()
            alerts.append(document)
        return alerts
    except Exception as e:
        raise internal_error("alerts_list_failed", e)

@router.get("/stats/by-rule")
async def alerts_by_rule(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Returns count of alerts grouped by rule_name."""
    try:
        pipeline = [
            {"$match": {"$and": [tenant_filter(user), {"rule_name": {"$exists": True, "$ne": None}}]}},
            {"$group": {"_id": "$rule_name", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        results = []
        async for doc in db["alerts"].aggregate(pipeline):
            results.append({"rule_name": doc["_id"], "count": doc["count"]})
        return results
    except Exception as e:
        logger.error(f"Error fetching rule stats: {e}")
        return []

@router.get("/stats/timeline")
async def alerts_timeline(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Returns alert counts grouped by detection hour (UTC) for the last 24 hours.

    created_at is the event time, which can be weeks old for backfilled data; detected_at is when
    Forensiq raised the alert. Older alerts without detected_at fall back to created_at.
    """
    try:
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        pipeline = [
            {"$match": tenant_filter(user)},
            {"$addFields": {"_detected": {"$ifNull": ["$detected_at", "$created_at"]}}},
            {"$match": {"_detected": {"$gte": twenty_four_hours_ago}}},
            {"$group": {
                "_id": {
                    "year": {"$year": "$_detected"},
                    "month": {"$month": "$_detected"},
                    "day": {"$dayOfMonth": "$_detected"},
                    "hour": {"$hour": "$_detected"}
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1, "_id.hour": 1}}
        ]
        results = []
        async for doc in db["alerts"].aggregate(pipeline):
            hour_str = f"{doc['_id']['hour']:02d}:00"
            results.append({"hour": hour_str, "count": doc["count"]})
        return results
    except Exception as e:
        logger.error(f"Error fetching timeline stats: {e}")
        return []

@router.get("/stats/mitre")
async def alerts_mitre_stats(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Returns aggregated MITRE ATT&CK techniques, tactics, hit counts, and rule coverage."""
    try:
        cursor = db["alerts"].find(
            scoped_query(user, {
                "$or": [
                    {"mitre_technique": {"$exists": True, "$ne": None, "$ne": ""}},
                    {"mitre_mappings": {"$exists": True, "$ne": []}}
                ]
            }),
            {"_id": 1, "title": 1, "severity": 1, "mitre_technique": 1, "mitre_tactic": 1, "mitre_mappings": 1}
        ).limit(500)
        
        tech_map = {}
        tactic_counts = {}
        total_mapped = 0
        
        async for doc in cursor:
            total_mapped += 1
            alert_id = str(doc.get("_id", ""))
            sev = (doc.get("severity") or "medium").lower()
            
            mappings = doc.get("mitre_mappings") or []
            if not mappings and doc.get("mitre_technique"):
                mappings = [{
                    "technique": doc.get("mitre_technique"),
                    "tactic": doc.get("mitre_tactic") or "Execution",
                    "name": doc.get("title") or ""
                }]
                
            for m in mappings:
                tech_id = str(m.get("technique") or "").strip().upper()
                if not tech_id:
                    continue
                tactic = str(m.get("tactic") or "Execution").strip()
                name = str(m.get("name") or "").strip()
                
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                
                if tech_id not in tech_map:
                    tech_map[tech_id] = {
                        "id": tech_id,
                        "name": name or tech_id,
                        "tactic": tactic,
                        "count": 0,
                        "severity": sev,
                        "alert_ids": []
                    }
                entry = tech_map[tech_id]
                entry["count"] += 1
                if alert_id and alert_id not in entry["alert_ids"]:
                    entry["alert_ids"].append(alert_id)
                
                sev_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                if sev_ranks.get(sev, 1) > sev_ranks.get(entry["severity"], 1):
                    entry["severity"] = sev

        return {
            "techniques": list(tech_map.values()),
            "tactics_summary": tactic_counts,
            "total_mapped_alerts": total_mapped
        }
    except Exception as e:
        logger.error(f"Error fetching MITRE stats: {e}")
        return {"techniques": [], "tactics_summary": {}, "total_mapped_alerts": 0}

@router.get("/{alert_id}", response_model=dict)
async def get_alert(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Fetches a single alert by ID, including context and enrichments if available."""
    try:
        alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Ensure proper serialization
        alert["_id"] = str(alert["_id"])
        alert["sla"] = sla_state(alert)
        for key in ("created_at", "detected_at", "acknowledged_at", "resolved_at", "assigned_at", "updated_at", "escalated_at"):
            if isinstance(alert.get(key), datetime):
                alert[key] = alert[key].isoformat()

        return alert
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error("alerts_endpoint_failed", e, alert_id=alert_id)

@router.post("/ingest", response_model=dict)
async def ingest_from_splunk(
    db: AsyncIOMotorDatabase = Depends(get_db),
    _user: dict = Depends(require_roles("admin", "soc_manager")),
):
    """Triggers a manual ingestion of alerts from Splunk into MongoDB."""
    try:
        service = IngestionService(db, tenant_id(_user))
        inserted = await service.fetch_and_store_alerts()
        result = {"status": "degraded" if service.errors else "success", "inserted": len(inserted), "fetched": service.total_fetched, "rules_run": service.rules_run, "errors": service.errors}
        if service.errors and not inserted:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail={"message": "Splunk ingestion failed", **result})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error("alerts_ingest_failed", e)


async def run_investigation_background(alert_id: str, job_id: str, db: AsyncIOMotorDatabase):
    """Background task to run the LangGraph pipeline with live event broadcasting."""
    try:
        alert = await db["alerts"].find_one({"_id": alert_id})
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        async for _ in investigation_stream_manager.run_pipeline_stream(
            alert_id=alert_id,
            alert=alert,
            db=db,
            job_id=job_id,
            org_id=alert.get("org_id", "default"),
        ):
            pass
        logger.info(f"Investigation {job_id} for alert {alert_id} completed successfully.")

    except Exception as e:
        ref = new_request_id()
        logger.error("investigation_failed", request_id=ref, job_id=job_id, alert_id=alert_id, error=str(e))
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.now(timezone.utc),
                "error": "investigation_failed",
                "error_ref": ref,
            }}
        )
        await db["alerts"].update_one(
            {"_id": alert_id},
            {"$set": {"status": "Investigation Failed"}}
        )


@router.post("/{alert_id:path}/investigate/stream")
async def investigate_alert_stream(
    alert_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Executes the LangGraph investigation pipeline and streams real-time Server-Sent Events (SSE)
    for each agent node to the client, while simultaneously broadcasting to any connected WebSockets.
    """
    try:
        alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        job_id = str(uuid.uuid4())
        org_id = tenant_id(user)

        async def sse_event_stream():
            try:
                async for event_item in investigation_stream_manager.run_pipeline_stream(
                    alert_id=alert_id,
                    alert=alert,
                    db=db,
                    job_id=job_id,
                    org_id=org_id,
                ):
                    event_name = event_item["event"]
                    event_data = json.dumps(event_item["data"], default=json_serial)
                    yield f"event: {event_name}\ndata: {event_data}\n\n"
            except Exception as e:
                ref = new_request_id()
                logger.error("sse_stream_exception", alert_id=alert_id, error=str(e))
                err_data = json.dumps({"job_id": job_id, "alert_id": alert_id, "error": f"Investigation failed (ref {ref})"})
                yield f"event: error\ndata: {err_data}\n\n"

        return StreamingResponse(
            sse_event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error("alerts_endpoint_failed", e, alert_id=alert_id)


@router.post("/{alert_id:path}/investigate", response_model=dict)
async def investigate_alert(
    alert_id: str, 
    background_tasks: BackgroundTasks,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Triggers the transparent MVP investigation pipeline using LangGraph."""
    try:
        alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        job_id = str(uuid.uuid4())
        
        await db["investigation_jobs"].insert_one({
            "_id": job_id,
            "alert_id": alert_id,
            "status": "pending",
            "created_at": datetime.utcnow()
            ,"org_id": tenant_id(user)
        })
        
        await db["alerts"].update_one(
            scoped_query(user, {"_id": alert_id}),
            {"$set": {"status": "Investigating"}}
        )
        
        background_tasks.add_task(run_investigation_background, alert_id, job_id, db)
        
        return {
            "status": "success",
            "job_id": job_id,
            "alert_id": alert_id,
            "message": "Investigation started in the background"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error("alerts_endpoint_failed", e, alert_id=alert_id)

def _sanitize_job(job: dict) -> dict:
    """Legacy job rows stored str(exception) in `error`; hide it unless it is a sanitized row (has error_ref)."""
    if job.get("error") and not job.get("error_ref"):
        job["error"] = "investigation_failed"
    return job


@router.get("/investigation/{job_id}", response_model=dict)
async def get_investigation_status(job_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Polls the status of an ongoing investigation."""
    try:
        job = await db["investigation_jobs"].find_one(scoped_query(user, {"_id": job_id}))
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        # Serialize datetime
        job["_id"] = str(job["_id"])
        for key in ["created_at", "started_at", "completed_at"]:
            if key in job and isinstance(job[key], datetime):
                job[key] = job[key].isoformat()
                
        return _sanitize_job(job)
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error("alerts_endpoint_failed", e, job_id=job_id)

@router.get("/{alert_id:path}/investigations")
async def investigation_history(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    if not await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}), {"_id": 1}):
        raise HTTPException(status_code=404, detail="Alert not found")
    jobs = []
    async for job in db["investigation_jobs"].find(scoped_query(user, {"alert_id": alert_id})).sort("created_at", -1).limit(20):
        job["_id"] = str(job["_id"])
        for key in ("created_at", "started_at", "completed_at"):
            if isinstance(job.get(key), datetime): job[key] = job[key].isoformat()
        jobs.append(_sanitize_job(job))
    return jobs

@router.post("/bulk")
async def bulk_action(payload: BulkRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Apply one action to many alerts. Each alert is checked on its own; failures do not stop the rest."""
    results = []
    for alert_id in dict.fromkeys(payload.alert_ids):  # de-duplicate, keep order
        try:
            if payload.action == "assign":
                await assign_alert(db, user, alert_id, payload.assignee_id)
            else:
                await apply_disposition(db, user, alert_id, payload.action, payload.verdict, payload.note)
            results.append({"alert_id": alert_id, "ok": True})
        except TriageError as exc:
            results.append({"alert_id": alert_id, "ok": False, "status_code": exc.status_code, "error": exc.detail})
    return {"succeeded": sum(r["ok"] for r in results), "failed": sum(not r["ok"] for r in results), "results": results}


@router.patch("/{alert_id:path}/disposition")
async def set_disposition(alert_id: str, payload: DispositionRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return await apply_disposition(db, user, alert_id, payload.action, payload.verdict, payload.note)
    except TriageError as exc:
        raise _triage_error(exc)


@router.patch("/{alert_id:path}/assignee")
async def set_assignee(alert_id: str, payload: AssignRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return await assign_alert(db, user, alert_id, payload.assignee_id)
    except TriageError as exc:
        raise _triage_error(exc)

@router.post("/{alert_id:path}/notes")
async def add_note(alert_id: str, payload: NoteRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    if not await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}), {"_id": 1}): raise HTTPException(status_code=404, detail="Alert not found")
    now = datetime.now(timezone.utc)
    note = {"_id": str(uuid.uuid4()), "org_id": tenant_id(user), "alert_id": alert_id, "content": payload.content, "author_email": user.get("email"), "created_at": now}
    await db["alert_notes"].insert_one(note)
    # A note is a human touching the alert: it starts the acknowledge clock if nothing else has.
    await db["alerts"].update_one(scoped_query(user, {"_id": alert_id, "acknowledged_at": {"$exists": False}}), {"$set": {"acknowledged_at": now}})
    await record_audit(db, user, "alert.note_added", "alert", alert_id, {"note_id": note["_id"]})
    note["created_at"] = note["created_at"].isoformat()
    return note

@router.get("/{alert_id:path}/notes")
async def list_notes(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    notes = []
    async for note in db["alert_notes"].find(scoped_query(user, {"alert_id": alert_id})).sort("created_at", 1):
        note["_id"] = str(note["_id"])
        if isinstance(note.get("created_at"), datetime): note["created_at"] = note["created_at"].isoformat()
        notes.append(note)
    return notes

@router.get("/{alert_id:path}/audit")
async def list_audit(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    logs = []
    async for entry in db["audit_logs"].find(scoped_query(user, {"entity_type": "alert", "entity_id": alert_id})).sort("created_at", -1).limit(100):
        entry["_id"] = str(entry["_id"])
        if isinstance(entry.get("created_at"), datetime): entry["created_at"] = entry["created_at"].isoformat()
        logs.append(entry)
    return logs

@router.get("/{alert_id:path}/report")
async def alert_report(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
    if not alert: raise HTTPException(status_code=404, detail="Alert not found")
    lines = [f"# Investigation report: {alert.get('title')}", "", f"- Status: {alert.get('status')}", f"- Severity: {alert.get('severity')}", f"- Risk: {alert.get('risk_score', 'pending')}/100", f"- Host: {alert.get('host')}", f"- User: {alert.get('user')}", "", "## Recommendation", alert.get("recommendation") or "Investigation has not completed.", "", "## MITRE mapping"]
    lines.extend(f"- {item.get('technique') or item.get('id')}: {item.get('name', '')}" for item in alert.get("mitre_mappings", []))
    lines += ["", "## Correlations"]
    lines.extend(f"- {item.get('title')} ({', '.join(match.get('type', '') for match in item.get('matches', []))})" for item in alert.get("correlations", []))
    return {"alert_id": alert_id, "markdown": "\n".join(lines)}
