"""
Alert Ingestion and Listing endpoints.
"""

from typing import List, Dict, Any, Literal, Optional
from datetime import datetime, timedelta, timezone
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
        cursor = db["alerts"].find(scoped_query(user, *conditions), {"raw_events": 0}).sort("created_at", -1).limit(limit)
        async for document in cursor:
            # Convert _id to string if it isn't already, ensure serializable
            document["_id"] = str(document["_id"])
            # Format datetime
            if "created_at" in document and isinstance(document["created_at"], datetime):
                document["created_at"] = document["created_at"].isoformat()
            alerts.append(document)
        return alerts
    except Exception as e:
        raise internal_error("alerts_list_failed", e)

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


async def _finalize_and_save_investigation(
    db: AsyncIOMotorDatabase,
    alert_id: str,
    job_id: str,
    alert: dict,
    final_state: dict,
) -> dict:
    """Consolidates graph state results and persists them to alerts and investigation_jobs."""
    enrichments = final_state.get("enrichment_results", [])
    context = final_state.get("context", {})
    extracted_iocs = final_state.get("extracted_iocs", [])
    investigation_log = final_state.get("investigation_log", [])
    risk_assessment = final_state.get("risk_assessment", {})
    mitre_mappings = final_state.get("mitre_mappings", [])
    timeline = final_state.get("timeline", [])
    recommendation = final_state.get("recommendation")
    correlations = final_state.get("correlations")
    if correlations is None:
        correlations = await correlate_alert(db, alert)
    evidence = {
        "ioc_count": len(extracted_iocs),
        "enrichment_count": len(enrichments),
        "correlated_alert_count": len(correlations),
        "mitre_count": len(mitre_mappings),
    }

    ai_confidence = risk_assessment.get("confidence_score", alert.get("ai_confidence", 50))
    for e in enrichments:
        if e.get("reputation") in ["malicious", "suspicious"]:
            ai_confidence = min(99, ai_confidence + 20)

    alert_update = {
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
    }

    await db["alerts"].update_one(
        {"_id": alert_id},
        {"$set": alert_update},
    )

    await db["investigation_jobs"].update_one(
        {"_id": job_id},
        {"$set": {
            "status": "complete",
            "completed_at": datetime.now(timezone.utc),
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
    logger.info("investigation_completed_and_saved", job_id=job_id, alert_id=alert_id)
    return {**alert, **alert_update}


async def run_investigation_background(alert_id: str, job_id: str, db: AsyncIOMotorDatabase):
    """Background task to run the LangGraph pipeline."""
    try:
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {"$set": {"status": "running", "started_at": datetime.now(timezone.utc)}}
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
            "correlations": [],
            "timeline": [],
            "recommendation": None,
        }

        final_state = await investigation_graph.ainvoke(initial_state)
        await _finalize_and_save_investigation(db, alert_id, job_id, alert, final_state)
        logger.info(f"Investigation {job_id} for alert {alert_id} completed successfully.")

    except Exception as e:
        ref = new_request_id()
        logger.error("investigation_failed", request_id=ref, job_id=job_id, alert_id=alert_id, error=str(e))
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.utcnow(),
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
    for each agent node to the client.
    """
    try:
        alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        job_id = str(uuid.uuid4())
        org_id = tenant_id(user)

        await db["investigation_jobs"].insert_one({
            "_id": job_id,
            "alert_id": alert_id,
            "status": "running",
            "created_at": datetime.now(timezone.utc),
            "started_at": datetime.now(timezone.utc),
            "org_id": org_id,
        })

        await db["alerts"].update_one(
            scoped_query(user, {"_id": alert_id}),
            {"$set": {"status": "Investigating"}}
        )

        async def sse_event_stream():
            step_definitions = {
                "extract_context": {
                    "step": 1,
                    "name": "Context Extraction",
                    "description": "Analyzing raw telemetry, host & user context",
                },
                "enrich_iocs": {
                    "step": 2,
                    "name": "Threat Intel & Cache Lookup",
                    "description": "Enriching IOCs via VirusTotal & AbuseIPDB with cache lookup",
                },
                "correlate_events": {
                    "step": 3,
                    "name": "Historical Event Correlation",
                    "description": "Searching across tenant alert history for related entities",
                },
                "map_mitre": {
                    "step": 4,
                    "name": "MITRE ATT&CK Mapping",
                    "description": "Mapping behavioral heuristics to MITRE tactics and techniques",
                },
                "build_timeline": {
                    "step": 5,
                    "name": "Chronological Timeline Assembly",
                    "description": "Sorting multi-source events into attack lifecycle phases",
                },
                "assess_risk": {
                    "step": 6,
                    "name": "AI Risk Assessment",
                    "description": "Evaluating threat severity, blast radius, and confidence score",
                },
                "generate_recommendations": {
                    "step": 7,
                    "name": "Incident Response Recommendations",
                    "description": "Synthesizing mitigation playbooks and actionable next steps",
                },
            }

            # 1. Send init event
            init_payload = {
                "job_id": job_id,
                "alert_id": alert_id,
                "total_steps": len(step_definitions),
                "status": "running",
                "message": "Investigation pipeline initialized",
            }
            yield f"event: init\ndata: {json.dumps(init_payload)}\n\n"

            initial_state = {
                "alert_data": alert,
                "context": {},
                "extracted_iocs": [],
                "enrichment_results": [],
                "investigation_log": [f"Investigation started for alert {alert_id}"],
                "ai_analysis": None,
                "risk_assessment": {},
                "mitre_mappings": [],
                "correlations": [],
                "timeline": [],
                "recommendation": None,
            }

            accumulated_state = dict(initial_state)

            try:
                async for chunk in investigation_graph.astream(initial_state):
                    for node_name, node_output in chunk.items():
                        accumulated_state.update(node_output)
                        meta = step_definitions.get(node_name, {
                            "step": 0,
                            "name": node_name,
                            "description": "",
                        })

                        summary = ""
                        if node_name == "extract_context":
                            iocs = node_output.get("extracted_iocs", [])
                            summary = f"Extracted {len(iocs)} indicators of compromise: {', '.join(iocs[:3])}" if iocs else "No distinct IOCs extracted from raw telemetry."
                        elif node_name == "enrich_iocs":
                            res = node_output.get("enrichment_results", [])
                            mal = sum(1 for r in res if r.get("reputation") == "malicious")
                            cached = sum(1 for r in res if r.get("cached"))
                            summary = f"Enriched {len(res)} threat feeds ({mal} malicious, {cached} cached)."
                        elif node_name == "correlate_events":
                            corrs = node_output.get("correlations", [])
                            summary = f"Correlated {len(corrs)} related alert(s) across historical telemetry."
                        elif node_name == "map_mitre":
                            mappings = node_output.get("mitre_mappings", [])
                            summary = f"Mapped {len(mappings)} MITRE technique(s): {', '.join(m.get('technique', '') for m in mappings[:2])}"
                        elif node_name == "build_timeline":
                            tl = node_output.get("timeline", [])
                            phases = {e.get("phase") for e in tl if e.get("phase")}
                            summary = f"Assembled {len(tl)} chronological events across {len(phases)} attack phase(s)."
                        elif node_name == "assess_risk":
                            risk = node_output.get("risk_assessment", {})
                            summary = f"Risk Score: {risk.get('risk_score', 0)}/100 ({risk.get('priority', 'medium').upper()} Priority)."
                        elif node_name == "generate_recommendations":
                            summary = "Actionable incident response checklist generated."

                        node_event = {
                            "job_id": job_id,
                            "node": node_name,
                            "step": meta["step"],
                            "name": meta["name"],
                            "description": meta["description"],
                            "status": "completed",
                            "summary": summary,
                            "data": {k: v for k, v in node_output.items() if k != "alert_data"},
                        }
                        yield f"event: node_complete\ndata: {json.dumps(node_event, default=str)}\n\n"

                # Persist final results into MongoDB
                final_alert = await _finalize_and_save_investigation(
                    db=db,
                    alert_id=alert_id,
                    job_id=job_id,
                    alert=alert,
                    final_state=accumulated_state,
                )

                serialized_alert = {}
                for k, v in final_alert.items():
                    if isinstance(v, datetime):
                        serialized_alert[k] = v.isoformat()
                    elif hasattr(v, "__str__") and k == "_id":
                        serialized_alert[k] = str(v)
                    else:
                        serialized_alert[k] = v

                complete_event = {
                    "job_id": job_id,
                    "alert_id": alert_id,
                    "status": "complete",
                    "message": "Investigation successfully finished",
                    "alert": serialized_alert,
                }
                yield f"event: complete\ndata: {json.dumps(complete_event, default=str)}\n\n"

            except Exception as e:
                ref = new_request_id()
                logger.error("investigation_stream_failed", request_id=ref, alert_id=alert_id, error=str(e))
                await db["investigation_jobs"].update_one(
                    {"_id": job_id},
                    {"$set": {"status": "failed", "completed_at": datetime.now(timezone.utc), "error": "investigation_failed", "error_ref": ref}}
                )
                await db["alerts"].update_one(
                    {"_id": alert_id},
                    {"$set": {"status": "Investigation Failed"}}
                )
                yield f"event: error\ndata: {json.dumps({'job_id': job_id, 'alert_id': alert_id, 'error': f'Investigation failed (ref {ref})'})}\n\n"

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
