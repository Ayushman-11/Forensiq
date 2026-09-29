"""
Alert Ingestion and Listing endpoints.
"""

from typing import List, Dict, Any, Literal, Optional
from datetime import datetime, timedelta
import uuid
import asyncio
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import AlertModel
from app.services.ingestion import IngestionService
from app.agents.graph import investigation_graph
from app.core.logging import logger
from app.api.deps import require_roles, get_current_user
from app.core.tenancy import scoped_query, tenant_filter, tenant_id
from app.services.audit import record_audit
from app.services.correlation import correlate_alert

router = APIRouter()

class DispositionRequest(BaseModel):
    action: Literal["close", "escalate", "suppress"]
    note: Optional[str] = Field(default=None, max_length=5000)

class NoteRequest(BaseModel):
    content: str = Field(min_length=1, max_length=5000)

@router.get("/", response_model=List[dict])
async def list_alerts(
    limit: int = 50,
    severity: str = Query(None, description="Filter by severity"),
    status: str = Query(None, description="Filter by status"),
    search: str = Query(None, description="Search in title or host"),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Fetches recent alerts from MongoDB with optional filtering."""
    try:
        conditions = []
        if severity and severity.lower() != "all":
            conditions.append({"severity": severity.lower()})
        if status and status.lower() != "all":
            conditions.append({"status": status})
            
        if search:
            conditions.append({"$or": [
                {"title": {"$regex": search, "$options": "i"}},
                {"host": {"$regex": search, "$options": "i"}}
            ]})
            
        alerts = []
        cursor = db["alerts"].find(scoped_query(user, *conditions)).sort("created_at", -1).limit(limit)
        async for document in cursor:
            # Convert _id to string if it isn't already, ensure serializable
            document["_id"] = str(document["_id"])
            # Format datetime
            if "created_at" in document and isinstance(document["created_at"], datetime):
                document["created_at"] = document["created_at"].isoformat()
            alerts.append(document)
        return alerts
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch alerts: {str(e)}",
        )

@router.get("/stats/by-rule")
async def alerts_by_rule(db: AsyncIOMotorDatabase = Depends(get_db)):
    """Returns count of alerts grouped by rule_name."""
    try:
        pipeline = [
            {"$match": {"rule_name": {"$exists": True, "$ne": None}}},
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
async def alerts_timeline(db: AsyncIOMotorDatabase = Depends(get_db)):
    """Returns alert counts grouped by hour for the last 24 hours."""
    try:
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        pipeline = [
            {"$match": {"created_at": {"$gte": twenty_four_hours_ago}}},
            {"$group": {
                "_id": {
                    "year": {"$year": "$created_at"},
                    "month": {"$month": "$created_at"},
                    "day": {"$dayOfMonth": "$created_at"},
                    "hour": {"$hour": "$created_at"}
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

@router.get("/{alert_id}", response_model=dict)
async def get_alert(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Fetches a single alert by ID, including context and enrichments if available."""
    try:
        alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Ensure proper serialization
        alert["_id"] = str(alert["_id"])
        if "created_at" in alert and isinstance(alert["created_at"], datetime):
            alert["created_at"] = alert["created_at"].isoformat()
            
        return alert
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion failed: {str(e)}"
        )


async def run_investigation_background(alert_id: str, job_id: str, db: AsyncIOMotorDatabase):
    """Background task to run the LangGraph pipeline."""
    try:
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {"$set": {"status": "running", "started_at": datetime.utcnow()}}
        )
        
        alert = await db["alerts"].find_one({"_id": alert_id})
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        initial_state = {
            "alert_data": alert,
            "context": {},
            "extracted_iocs": [],
            "enrichment_results": [],
            "investigation_log": [f"Investigation started for alert {alert_id}"],
            "ai_analysis": None,
            "risk_assessment": {},
            "mitre_mappings": [],
            "timeline": [],
            "recommendation": None,
        }
        
        # Run graph
        final_state = await investigation_graph.ainvoke(initial_state)
        
        enrichments = final_state.get("enrichment_results", [])
        context = final_state.get("context", {})
        extracted_iocs = final_state.get("extracted_iocs", [])
        investigation_log = final_state.get("investigation_log", [])
        risk_assessment = final_state.get("risk_assessment", {})
        mitre_mappings = final_state.get("mitre_mappings", [])
        timeline = final_state.get("timeline", [])
        recommendation = final_state.get("recommendation")
        correlations = await correlate_alert(db, alert)
        evidence = {"ioc_count": len(extracted_iocs), "enrichment_count": len(enrichments), "correlated_alert_count": len(correlations), "mitre_count": len(mitre_mappings)}
        
        # Calculate mock AI confidence based on enrichments
        ai_confidence = risk_assessment.get("confidence_score", alert.get("ai_confidence", 50))
        for e in enrichments:
            if e.get("reputation") in ["malicious", "suspicious"]:
                ai_confidence = min(99, ai_confidence + 20)
                
        # Update Alert
        await db["alerts"].update_one(
            {"_id": alert_id},
            {"$set": {
                "status": "Investigated",
                "ai_confidence": ai_confidence,
                "context": context,
                "enrichments": enrichments,
                "extracted_iocs": extracted_iocs,
                "risk_assessment": risk_assessment,
                "risk_score": risk_assessment.get("risk_score", 0),
                "priority": risk_assessment.get("priority", "medium"),
                "mitre_mappings": mitre_mappings,
                "timeline": timeline,
                "recommendation": recommendation,
                "correlations": correlations,
                "evidence": evidence,
            }}
        )
        
        # Mark job complete
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {"$set": {
                "status": "complete", 
                "completed_at": datetime.utcnow(),
                "logs": investigation_log,
                "context": context,
                "enrichments": enrichments,
                "risk_assessment": risk_assessment,
                "mitre_mappings": mitre_mappings,
                "timeline": timeline,
                "recommendation": recommendation,
                "correlations": correlations,
                "evidence": evidence,
            }}
        )
        logger.info(f"Investigation {job_id} for alert {alert_id} completed successfully.")
        
    except Exception as e:
        logger.error(f"Investigation {job_id} failed: {e}")
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {"$set": {
                "status": "failed", 
                "completed_at": datetime.utcnow(),
                "error": str(e)
            }}
        )
        await db["alerts"].update_one(
            {"_id": alert_id},
            {"$set": {"status": "Investigation Failed"}}
        )

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
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigation/{job_id}", response_model=dict)
async def get_investigation_status(job_id: str, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Polls the status of an ongoing investigation."""
    try:
        job = await db["investigation_jobs"].find_one({"_id": job_id})
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        # Serialize datetime
        job["_id"] = str(job["_id"])
        for key in ["created_at", "started_at", "completed_at"]:
            if key in job and isinstance(job[key], datetime):
                job[key] = job[key].isoformat()
                
        return job
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{alert_id:path}/investigations")
async def investigation_history(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    if not await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}), {"_id": 1}):
        raise HTTPException(status_code=404, detail="Alert not found")
    jobs = []
    async for job in db["investigation_jobs"].find(scoped_query(user, {"alert_id": alert_id})).sort("created_at", -1).limit(20):
        job["_id"] = str(job["_id"])
        for key in ("created_at", "started_at", "completed_at"):
            if isinstance(job.get(key), datetime): job[key] = job[key].isoformat()
        jobs.append(job)
    return jobs

@router.patch("/{alert_id:path}/disposition")
async def set_disposition(alert_id: str, payload: DispositionRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    statuses = {"close": "Closed", "escalate": "Escalated", "suppress": "Suppressed"}
    update = {"status": statuses[payload.action], "disposition": payload.action, "updated_at": datetime.utcnow()}
    if payload.note: update["disposition_note"] = payload.note
    result = await db["alerts"].update_one(scoped_query(user, {"_id": alert_id}), {"$set": update})
    if not result.matched_count: raise HTTPException(status_code=404, detail="Alert not found")
    await record_audit(db, user, f"alert.{payload.action}", "alert", alert_id, {"note": payload.note} if payload.note else {})
    return {"status": update["status"], "alert_id": alert_id}

@router.post("/{alert_id:path}/notes")
async def add_note(alert_id: str, payload: NoteRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    if not await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}), {"_id": 1}): raise HTTPException(status_code=404, detail="Alert not found")
    note = {"_id": str(uuid.uuid4()), "org_id": tenant_id(user), "alert_id": alert_id, "content": payload.content, "author_email": user.get("email"), "created_at": datetime.utcnow()}
    await db["alert_notes"].insert_one(note)
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
