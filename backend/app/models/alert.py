from typing import Optional, List, Any
from datetime import datetime
from pydantic import BaseModel, Field

class AlertModel(BaseModel):
    id: str = Field(alias="_id")
    title: str
    severity: str
    host: str
    user: str
    ai_confidence: int
    status: str
    created_at: datetime
    
    class Config:
        populate_by_name = True

class DashboardMetrics(BaseModel):
    total_alerts: int
    critical_alerts: int
    open_investigations: int
    ai_confidence_avg: int
    mttd_seconds: int
    intel_hits: int
