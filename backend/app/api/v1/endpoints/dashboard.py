from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import DashboardMetrics

router = APIRouter()

@router.get("/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(db: AsyncIOMotorDatabase = Depends(get_db)):
    """Fetches KPI metrics for the dashboard from MongoDB."""
    total_alerts = await db["alerts"].count_documents({})
    critical_alerts = await db["alerts"].count_documents({"severity": {"$regex": "^critical$", "$options": "i"}})
    new_alerts = await db["alerts"].count_documents({"status": "New"})
    high_priority_alerts = await db["alerts"].count_documents({"severity": {"$in": ["critical", "high"]}, "status": {"$in": ["New", "Investigating"]}})
    open_investigations = await db["alerts"].count_documents({"status": "Investigating"})
    investigated_alerts = await db["alerts"].count_documents({"status": "Investigated"})
    
    if total_alerts > 0:
        pipeline = [{"$group": {"_id": None, "avg_conf": {"$avg": "$ai_confidence"}}}]
        cursor = db["alerts"].aggregate(pipeline)
        result = await cursor.to_list(length=1)
        ai_confidence_avg = int(result[0]["avg_conf"]) if result else 0
    else:
        ai_confidence_avg = 0
        
    ingestion_state = await db["ingestion_state"].find_one({"_id": "last_ingested"})
    last_ingested_at = ingestion_state.get("ts") if ingestion_state else None

    return DashboardMetrics(
        total_alerts=total_alerts,
        new_alerts=new_alerts,
        critical_alerts=critical_alerts,
        high_priority_alerts=high_priority_alerts,
        open_investigations=open_investigations,
        investigated_alerts=investigated_alerts,
        ai_confidence_avg=ai_confidence_avg,
        last_ingested_at=last_ingested_at,
    )
