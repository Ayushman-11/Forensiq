"""SIEM-agnostic cleaned event produced by the mappers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CanonicalEvent(BaseModel):
    event_id: str
    ts: datetime
    event_code: str
    source: str = "splunk"

    host: str | None = None
    host_key: str | None = None
    user: str | None = None
    user_display: str | None = None
    account_domain: str | None = None

    process: str | None = None
    process_path: str | None = None
    parent: str | None = None
    parent_path: str | None = None
    command_line: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)

    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    initiated: bool | None = None

    query_name: str | None = None
    query_results: str | None = None
    registry_key: str | None = None
    registry_details: str | None = None

    logon_type: str | None = None
    failure_reason: str | None = None
    workstation: str | None = None
    subject_user: str | None = None
    target_user: str | None = None
    target_domain: str | None = None
    script_block: str | None = None

    fields: dict[str, str] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    cleaning_notes: list[str] = Field(default_factory=list)
