from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import DashboardMetrics

router = APIRouter()

@router.get("/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(db: AsyncIOMotorDatabase = Depends(get_db)):
    """Fetches KPI metrics for the dashboard from MongoDB."""
    total_alerts = await db["alerts"].count_documents({})
    critical_alerts = await db["alerts"].count_documents({"severity": "Critical"})
    open_investigations = await db["alerts"].count_documents({"status": "Investigating"})
    
    # Simple aggregates (mocked or calculated)
    # AI confidence avg could be calculated, we just hardcode/mock slightly if no alerts
    if total_alerts > 0:
        pipeline = [{"$group": {"_id": None, "avg_conf": {"$avg": "$ai_confidence"}}}]
        cursor = db["alerts"].aggregate(pipeline)
        result = await cursor.to_list(length=1)
        ai_confidence_avg = int(result[0]["avg_conf"]) if result else 0
    else:
        ai_confidence_avg = 0
        
    return DashboardMetrics(
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        open_investigations=open_investigations,
        ai_confidence_avg=ai_confidence_avg,
        mttd_seconds=268, # 4m 28s mock
        intel_hits=156    # Mock
    )
