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
    alert_type: str | None = None
    rule_name: str | None = None
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    event_code: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    dest_port: str | None = None
    protocol: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    registry_key: str | None = None
    dns_query: str | None = None
    hashes: str | None = None
    extracted_iocs: list[str] | None = None
    description: str | None = None
    source_siem: str | None = None
    risk_score: int | None = None
    priority: str | None = None
    recommendation: str | None = None
    risk_assessment: dict | None = None
    mitre_mappings: list[dict] | None = None
    timeline: list[dict] | None = None
    correlations: list[dict] | None = None
    evidence: dict | None = None

    class Config:
        populate_by_name = True


class DashboardMetrics(BaseModel):
    total_alerts: int
    new_alerts: int
    critical_alerts: int
    high_priority_alerts: int
    open_investigations: int
    investigated_alerts: int
    ai_confidence_avg: int
    last_ingested_at: str | None = None
