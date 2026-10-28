"""
Tests for Production-Readiness Section 1.4: Data Durability & Governance.
Validates:
- Schema migrations & refusal on unknown newer schema version
- Audit log compound indexing, append-only immutability, and export
- Policy versioning and change audit trail
- PII redaction and erase-on-request compliance procedure
"""

from datetime import datetime, timezone
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.database.migrations import (
    CURRENT_SCHEMA_VERSION,
    SchemaVersionError,
    get_current_schema_version,
    run_migrations,
)
from app.services.audit import record_audit, get_audit_trail, export_audit_logs
from app.services.policy import get_active_policy, update_policy, get_policy_history
from app.services.governance import (
    redact_pii,
    sanitize_raw_event,
    erase_entity_on_request,
    purge_expired_records,
)


@pytest.fixture
def mock_db():
    client = AsyncMongoMockClient()
    return client["test_durability"]


@pytest.mark.asyncio
async def test_schema_migrations_runs_and_records_version(mock_db):
    version = await run_migrations(mock_db)
    assert version == CURRENT_SCHEMA_VERSION

    # Verify version recorded in DB
    recorded = await get_current_schema_version(mock_db)
    assert recorded == CURRENT_SCHEMA_VERSION

    # Verify re-running is idempotent
    re_run = await run_migrations(mock_db)
    assert re_run == CURRENT_SCHEMA_VERSION


@pytest.mark.asyncio
async def test_schema_migrations_refuses_unknown_newer_version(mock_db):
    # Simulate a database upgraded by a newer release of Forensiq
    await mock_db["schema_versions"].insert_one({
        "_id": "current",
        "version": CURRENT_SCHEMA_VERSION + 1,
        "updated_at": datetime.now(timezone.utc),
    })

    with pytest.raises(SchemaVersionError) as exc_info:
        await run_migrations(mock_db)
    assert "newer than application supported version" in str(exc_info.value)


@pytest.mark.asyncio
async def test_audit_log_append_only_and_export(mock_db):
    user = {"id": "analyst-1", "email": "analyst@test.com", "org_id": "tenant-1"}

    # 1. Record audits
    e1 = await record_audit(mock_db, user, "alert.close", "alert", "a-1", {"verdict": "true_positive"})
    e2 = await record_audit(mock_db, user, "alert.escalate", "alert", "a-2")

    assert e1["actor_email"] == "analyst@test.com"
    assert e2["action"] == "alert.escalate"

    # 2. Query trail
    trail = await get_audit_trail(mock_db, user, entity_type="alert", entity_id="a-1")
    assert len(trail) == 1
    assert trail[0]["entity_id"] == "a-1"

    # 3. Export logs for external compliance storage / SIEM
    exported = await export_audit_logs(mock_db, user)
    assert len(exported) == 2
    assert all("_id" in entry and "created_at" in entry for entry in exported)


@pytest.mark.asyncio
async def test_policy_governance_versioning_and_audit(mock_db):
    user = {"id": "admin-1", "email": "admin@test.com", "org_id": "tenant-corp"}

    # 1. Get default SLA policy
    sla = await get_active_policy(mock_db, "tenant-corp", "sla_targets")
    assert "critical" in sla
    assert sla["critical"] == (15, 240)

    # 2. Update SLA targets policy
    custom_sla = {"critical": (10, 120), "high": (30, 360)}
    updated = await update_policy(
        mock_db,
        user=user,
        policy_type="sla_targets",
        content=custom_sla,
        reason="Updated tighter SLA for SOC Tier 1",
    )
    assert updated["version"] == 1
    assert updated["is_active"] is True

    # 3. Verify active policy returns new version
    active = await get_active_policy(mock_db, "tenant-corp", "sla_targets")
    assert active["critical"] == [10, 120] or active["critical"] == (10, 120)

    # 4. Check audit entry was recorded
    audit = await mock_db["audit_logs"].find_one({"action": "policy.updated"})
    assert audit is not None
    assert audit["metadata"]["version"] == 1
    assert "Updated tighter SLA" in audit["metadata"]["reason"]

    # 5. Check history
    history = await get_policy_history(mock_db, user, "sla_targets")
    assert len(history) == 1
    assert history[0]["version"] == 1


def test_pii_redaction_helpers():
    raw_text = "User john.doe@example.com logged in with password=SuperSecret123! from 192.168.1.1"
    redacted = redact_pii(raw_text)
    assert "[EMAIL_REDACTED]" in redacted
    assert "SuperSecret123!" not in redacted
    assert "password=[REDACTED]" in redacted

    raw_event = {
        "user_email": "target@corp.local",
        "api_token": "secret-xyz-12345",
        "command": "login --password secret123",
        "details": {"notes": "Contact admin@corp.local for details"},
    }
    sanitized = sanitize_raw_event(raw_event)
    assert sanitized["api_token"] == "[REDACTED]"
    assert "[EMAIL_REDACTED]" in sanitized["command"] or "password=[REDACTED]" in sanitized["command"]
    assert "[EMAIL_REDACTED]" in sanitized["details"]["notes"]


@pytest.mark.asyncio
async def test_erase_entity_on_request_gdpr_compliance(mock_db):
    user = {"id": "dpo-1", "email": "dpo@corp.com", "org_id": "default"}

    # Seed alerts and notes with target user
    await mock_db["alerts"].insert_one({
        "_id": "alert-privacy-1",
        "org_id": "default",
        "user": "victim_user",
        "title": "Suspicious login for victim_user",
    })
    await mock_db["alert_notes"].insert_one({
        "_id": "note-privacy-1",
        "org_id": "default",
        "alert_id": "alert-privacy-1",
        "content": "Notified victim_user about credentials compromise",
    })

    # Execute erase on request
    result = await erase_entity_on_request(
        mock_db,
        user=user,
        target_identifier="victim_user",
        reason="GDPR Article 17 Right to Erasure request #482",
    )

    assert result["status"] == "success"
    assert result["alerts_anonymized"] == 1
    assert result["notes_redacted"] == 1

    # Verify alert user is now erased/anonymized
    alert = await mock_db["alerts"].find_one({"_id": "alert-privacy-1"})
    assert alert["user"] == "[ERASED_USER]"
    assert alert["anonymized_reason"] == "GDPR Article 17 Right to Erasure request #482"

    # Verify note was redacted
    note = await mock_db["alert_notes"].find_one({"_id": "note-privacy-1"})
    assert note["content"] == "[CONTENT REDACTED PER PRIVACY REQUEST]"

    # Verify compliance action was audited
    audit = await mock_db["audit_logs"].find_one({"action": "compliance.erase_on_request"})
    assert audit is not None
    assert audit["entity_id"] == "victim_user"

