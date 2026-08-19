"""
Alert Ingestion and Listing endpoints.
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta
import uuid
import asyncio
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import AlertModel
from app.services.ingestion import IngestionService
from app.agents.graph import investigation_graph
from app.core.logging import logger
from app.api.deps import require_roles

router = APIRouter()

@router.get("/", response_model=List[dict])
async def list_alerts(
    limit: int = 50,
    severity: str = Query(None, description="Filter by severity"),
    status: str = Query(None, description="Filter by status"),
    search: str = Query(None, description="Search in title or host"),
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    """Fetches recent alerts from MongoDB with optional filtering."""
    try:
        query = {}
        if severity and severity.lower() != "all":
            query["severity"] = severity.lower()
        if status and status.lower() != "all":
            query["status"] = status
            
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"host": {"$regex": search, "$options": "i"}}
            ]
            
        alerts = []
        cursor = db["alerts"].find(query).sort("created_at", -1).limit(limit)
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
async def get_alert(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Fetches a single alert by ID, including context and enrichments if available."""
    try:
        alert = await db["alerts"].find_one({"_id": alert_id})
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
        service = IngestionService(db)
        inserted = await service.fetch_and_store_alerts()
        return {"status": "success", "inserted": len(inserted)}
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
            "ai_analysis": None
        }
        
        # Run graph
        final_state = await investigation_graph.ainvoke(initial_state)
        
        enrichments = final_state.get("enrichment_results", [])
        context = final_state.get("context", {})
        extracted_iocs = final_state.get("extracted_iocs", [])
        investigation_log = final_state.get("investigation_log", [])
        
        # Calculate mock AI confidence based on enrichments
        ai_confidence = alert.get("ai_confidence", 50)
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
                "extracted_iocs": extracted_iocs
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
                "enrichments": enrichments
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
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    """Triggers an async AI Agent pipeline (Context & IOC Enrichment) using LangGraph."""
    try:
        alert = await db["alerts"].find_one({"_id": alert_id})
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        job_id = str(uuid.uuid4())
        
        await db["investigation_jobs"].insert_one({
            "_id": job_id,
            "alert_id": alert_id,
            "status": "pending",
            "created_at": datetime.utcnow()
        })
        
        await db["alerts"].update_one(
            {"_id": alert_id},
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
