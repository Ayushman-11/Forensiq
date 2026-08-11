"""
Alert Ingestion and Listing endpoints.
"""

from typing import List
from datetime import datetime
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import AlertModel

router = APIRouter()

@router.get("/", response_model=List[AlertModel])
async def list_alerts(
    limit: int = 50,
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    """Fetches recent alerts from MongoDB."""
    try:
        alerts = []
        cursor = db["alerts"].find({}).sort("created_at", -1).limit(limit)
        async for document in cursor:
            alerts.append(AlertModel(**document))
        return alerts
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch alerts: {str(e)}",
        )

@router.post("/seed", response_model=dict)
async def seed_alerts(db: AsyncIOMotorDatabase = Depends(get_db)):
    """Seeds the MongoDB with mock alerts for testing the UI."""
    await db["alerts"].delete_many({}) # Clear existing
    
    mock_alerts = [
        {
            "_id": str(uuid.uuid4()),
            "title": "Suspicious PowerShell Execution",
            "severity": "Critical",
            "host": "SRV-PROD-09",
            "user": "svc_backup",
            "ai_confidence": 98,
            "status": "Investigating",
            "created_at": datetime.utcnow()
        },
        {
            "_id": str(uuid.uuid4()),
            "title": "Multiple Failed Logins",
            "severity": "High",
            "host": "WKSTN-1142",
            "user": "j.doe",
            "ai_confidence": 85,
            "status": "New",
            "created_at": datetime.utcnow()
        },
        {
            "_id": str(uuid.uuid4()),
            "title": "Unusual Outbound Traffic",
            "severity": "Medium",
            "host": "SRV-DEV-02",
            "user": "SYSTEM",
            "ai_confidence": 62,
            "status": "Auto-Closed",
            "created_at": datetime.utcnow()
        }
    ]
    
    await db["alerts"].insert_many(mock_alerts)
    return {"status": "success", "inserted": len(mock_alerts)}

from app.services.ingestion import IngestionService

@router.post("/ingest", response_model=dict)
async def ingest_from_splunk(db: AsyncIOMotorDatabase = Depends(get_db)):
    """Triggers a manual ingestion of alerts from Splunk into MongoDB."""
    try:
        service = IngestionService(db)
        inserted = await service.fetch_and_store_alerts()
        return {"status": "success", "inserted": inserted}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion failed: {str(e)}"
        )

from app.agents.graph import investigation_graph

@router.post("/{alert_id:path}/investigate", response_model=dict)
async def investigate_alert(alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Runs the AI Agent pipeline (Context & IOC Enrichment) using LangGraph on a specific alert."""
    try:
        # Fetch the alert
        alert = await db["alerts"].find_one({"_id": alert_id})
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        # 1. Initialize LangGraph State
        initial_state = {
            "alert_data": alert,
            "extracted_iocs": [],
            "enrichment_results": [],
            "ai_analysis": None
        }
        
        # 2. Execute Graph
        # invoke is a sync/async method depending on how it's called. Since our nodes might have async operations,
        # we should use ainvoke
        final_state = await investigation_graph.ainvoke(initial_state)
        
        enrichments = final_state.get("enrichment_results", [])
        extracted_iocs = final_state.get("extracted_iocs", [])
        
        # Calculate mock AI confidence based on enrichments
        ai_confidence = 50
        for e in enrichments:
            if e.get("reputation") == "suspicious":
                ai_confidence = min(99, ai_confidence + 20)
                
        # Update MongoDB with investigation results
        await db["alerts"].update_one(
            {"_id": alert_id},
            {"$set": {
                "status": "Investigating",
                "ai_confidence": ai_confidence,
                "enrichments": enrichments,
                "extracted_iocs": extracted_iocs
            }}
        )
        
        return {
            "status": "success",
            "alert_id": alert_id,
            "context_extracted": {
                "total_iocs": len(extracted_iocs)
            },
            "enrichments_completed": len(enrichments),
            "new_ai_confidence": ai_confidence
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

