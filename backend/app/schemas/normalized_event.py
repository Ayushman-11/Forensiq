"""
Normalized Security Event & Alert Schema definitions.
Provides standard, SIEM-agnostic fields for events, alerts, and indicators across all telemetry providers.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NormalizedEvent(BaseModel):
    """
    Standardized, SIEM-agnostic event model representing telemetry across Windows, Linux, Sysmon, and EDR.
    """
    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime = Field(..., description="UTC Event generation timestamp")
    event_id: str = Field(..., description="Provider-specific event ID (e.g. Sysmon EventCode 1)")
    provider: str = Field(..., description="Telemetry source provider (e.g. Sysmon, WindowsEventLog, CrowdStrike)")
    hostname: str = Field(..., description="Host system FQDN or NetBIOS name")
    user: str | None = Field(default=None, description="Target or execution username")
    domain: str | None = Field(default=None, description="User domain or host domain")

    # Process Telemetry
    process_name: str | None = Field(default=None, description="Executable process name")
    process_path: str | None = Field(default=None, description="Full image process path")
    command_line: str | None = Field(default=None, description="Full execution command line including flags")
    parent_process_name: str | None = Field(default=None, description="Parent process executable name")
    parent_command_line: str | None = Field(default=None, description="Parent process command line")
    process_id: int | None = Field(default=None, description="Process PID")
    parent_process_id: int | None = Field(default=None, description="Parent process PID")

    # Network Telemetry
    source_ip: str | None = Field(default=None, description="Source IP address")
    source_port: int | None = Field(default=None, description="Source network port")
    destination_ip: str | None = Field(default=None, description="Destination IP address")
    destination_port: int | None = Field(default=None, description="Destination network port")
    protocol: str | None = Field(default=None, description="Network transport protocol (TCP, UDP)")

    # Registry / System Telemetry
    registry_target_object: str | None = Field(default=None, description="Target registry key or value path")
    registry_details: str | None = Field(default=None, description="Registry modification value details")

    # Classification & Enrichment
    severity: str = Field(default="informational", description="Event severity (informational, low, medium, high, critical)")
    mitre_technique_id: str | None = Field(default=None, description="Mapped MITRE ATT&CK Technique ID (e.g. T1059.001)")
    mitre_tactic: str | None = Field(default=None, description="Mapped MITRE ATT&CK Tactic (e.g. Execution)")
    risk_score: float = Field(default=0.0, description="Calculated event risk score (0 - 100)")
    raw_payload: dict[str, Any] = Field(default_factory=dict, description="Original unmodified SIEM JSON payload")


class NormalizedAlert(BaseModel):
    """
    Standardized, SIEM-agnostic alert object for ingested SIEM triggers and alerts.
    """
    model_config = ConfigDict(from_attributes=True)

    alert_id: str = Field(..., description="Unique alert identifier from SIEM")
    title: str = Field(..., description="Alert rule title or signature name")
    description: str | None = Field(default=None, description="Alert description")
    severity: str = Field(default="medium", description="Alert severity level")
    created_at: datetime = Field(..., description="Alert creation timestamp")
    source_siem: str = Field(default="splunk", description="SIEM system originating the alert")
    event_count: int = Field(default=1, description="Number of underlying correlated events")
    affected_hostname: str | None = Field(default=None, description="Primary affected host")
    affected_user: str | None = Field(default=None, description="Primary affected user")
    mitre_techniques: list[str] = Field(default_factory=list, description="List of mapped MITRE ATT&CK techniques")
    raw_alert_data: dict[str, Any] = Field(default_factory=dict, description="Raw alert payload from SIEM")
