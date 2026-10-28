"""
SQLAlchemy ORM Models for Incidents and Ingested Alerts.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import String, DateTime, Text, Float, Integer, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base


class Incident(Base):
    """
    Represents an Investigation Incident aggregated across SIEM alerts and AI agent analysis.
    """
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(50), default="medium", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    affected_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    affected_user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    alerts: Mapped[List["AlertRecord"]] = relationship("AlertRecord", back_populates="incident", cascade="all, delete-orphan")


class AlertRecord(Base):
    """
    Represents an ingested SIEM alert stored in PostgreSQL.
    """
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    splunk_alert_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    source_siem: Mapped[str] = mapped_column(String(50), default="splunk")
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    incident: Mapped[Optional[Incident]] = relationship("Incident", back_populates="alerts")
