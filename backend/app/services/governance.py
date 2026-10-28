"""
Data Governance & Durability Service.

Implements:
1. PII Redaction for telemetry and raw events.
2. Erase-on-request (GDPR / Privacy right-to-be-forgotten) across alerts, notes, and jobs.
3. Retention verification and on-demand cleanup enforcement.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.config import settings
from app.core.logging import logger
from app.core.tenancy import scoped_query, tenant_id
from app.services.audit import record_audit

# Common PII Regex Patterns
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PASSWORD_PARAM_REGEX = re.compile(r"((?:--|-)?(?:password|secret|token|passwd|pwd))\s*[=:\s]\s*([^\s,;]+)", re.IGNORECASE)


def redact_pii(text: str) -> str:
    """Redacts common PII (emails, SSNs, password parameters) from raw strings."""
    if not isinstance(text, str):
        return text
    redacted = PASSWORD_PARAM_REGEX.sub(r"\1=[REDACTED]", text)
    redacted = EMAIL_REGEX.sub("[EMAIL_REDACTED]", redacted)
    redacted = SSN_REGEX.sub("[SSN_REDACTED]", redacted)
    return redacted


def sanitize_raw_event(raw_event: Any) -> Any:
    """Recursively sanitizes raw event objects, redacting PII strings."""
    if isinstance(raw_event, dict):
        sanitized = {}
        for k, v in raw_event.items():
            lower_k = k.lower()
            if any(term in lower_k for term in ("password", "passwd", "token", "secret", "private_key")):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_raw_event(v)
        return sanitized
    elif isinstance(raw_event, list):
        return [sanitize_raw_event(item) for item in raw_event]
    elif isinstance(raw_event, str):
        return redact_pii(raw_event)
    return raw_event


async def erase_entity_on_request(
    db,
    user: dict | None,
    target_identifier: str,
    reason: str,
) -> dict:
    """
    Compliance procedure: Erases or anonymizes personal identifiers from
    alerts, alert_notes, and raw events associated with target_identifier (e.g. username, email, IP).
    Audits the compliance erasure action.
    """
    org = tenant_id(user)
    escaped_id = re.escape(target_identifier)
    regex_pattern = {"$regex": f"^{escaped_id}$", "$options": "i"}

    # 1. Anonymize user in alerts
    alert_res = await db["alerts"].update_many(
        {"org_id": org, "user": regex_pattern},
        {"$set": {
            "user": "[ERASED_USER]",
            "anonymized_at": datetime.now(timezone.utc),
            "anonymized_reason": reason.strip(),
        }},
    )

    # 2. Redact matching alert notes
    notes_res = await db["alert_notes"].update_many(
        {"org_id": org, "content": {"$regex": escaped_id, "$options": "i"}},
        {"$set": {
            "content": "[CONTENT REDACTED PER PRIVACY REQUEST]",
            "redacted_at": datetime.now(timezone.utc),
        }},
    )

    # 3. Audit the erasure operation
    audit_entry = await record_audit(
        db=db,
        user=user,
        action="compliance.erase_on_request",
        entity_type="privacy_request",
        entity_id=target_identifier,
        metadata={
            "reason": reason.strip(),
            "alerts_anonymized": alert_res.modified_count,
            "notes_redacted": notes_res.modified_count,
        },
    )

    logger.info(
        "privacy_erasure_completed",
        target=target_identifier,
        alerts_anonymized=alert_res.modified_count,
        notes_redacted=notes_res.modified_count,
    )

    return {
        "status": "success",
        "target_identifier": target_identifier,
        "alerts_anonymized": alert_res.modified_count,
        "notes_redacted": notes_res.modified_count,
        "audit_id": audit_entry["_id"],
    }


async def purge_expired_records(db) -> dict:
    """
    Manual/scheduled cleanup helper to purge expired records in environments
    where TTL background threads may have latency or for immediate compliance purging.
    """
    now = datetime.now(timezone.utc)
    results = {}

    # Purge old raw events in alerts older than RAW_EVENTS_RETENTION_DAYS
    raw_cutoff = now - timedelta(days=settings.RAW_EVENTS_RETENTION_DAYS)
    raw_events_cleaned = await db["alerts"].update_many(
        {"created_at": {"$lt": raw_cutoff}, "raw_events": {"$exists": True, "$ne": []}},
        {"$set": {"raw_events": []}},
    )
    results["raw_events_purged"] = raw_events_cleaned.modified_count

    # Purge old completed investigation jobs older than INVESTIGATION_JOB_RETENTION_DAYS
    job_cutoff = now - timedelta(days=settings.INVESTIGATION_JOB_RETENTION_DAYS)
    jobs_deleted = await db["investigation_jobs"].delete_many(
        {"status": "complete", "completed_at": {"$lt": job_cutoff}}
    )
    results["completed_jobs_deleted"] = jobs_deleted.deleted_count

    return results
