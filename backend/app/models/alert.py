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
    # New real-data fields (all optional for backward compat)
    alert_type: Optional[str] = None
    rule_name: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    event_code: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[str] = None
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    registry_key: Optional[str] = None
    dns_query: Optional[str] = None
    hashes: Optional[str] = None
    extracted_iocs: Optional[List[str]] = None
    description: Optional[str] = None
    source_siem: Optional[str] = None

    class Config:
        populate_by_name = True


class DashboardMetrics(BaseModel):
    total_alerts: int
    critical_alerts: int
    open_investigations: int
    ai_confidence_avg: int
    mttd_seconds: int
    intel_hits: int
