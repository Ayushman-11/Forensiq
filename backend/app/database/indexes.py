"""MongoDB index definitions and versioned migrations, executed idempotently at startup."""

from __future__ import annotations

from app.database.migrations import CURRENT_SCHEMA_VERSION, run_migrations

RUNS_TTL_SECONDS = 30 * 24 * 3600
WS_TICKETS_TTL_SECONDS = 120  # Expire unconsumed tickets after 2 minutes


async def ensure_indexes(db) -> None:
    alerts = db["alerts"]
    await alerts.create_index([("org_id", 1), ("created_at", -1)])
    await alerts.create_index("host")
    await alerts.create_index("user")
    await alerts.create_index("extracted_iocs")
    await alerts.create_index("status")
    await alerts.create_index([("org_id", 1), ("incident_id", 1)])
    incidents = db["incidents"]
    await incidents.create_index([("org_id", 1), ("keys", 1), ("last_seen", -1)])
    await incidents.create_index([("org_id", 1), ("last_seen", -1)])
    await db["response_requests"].create_index([("org_id", 1), ("status", 1), ("requested_at", -1)])
    await db["response_requests"].create_index([("org_id", 1), ("action_type", 1), ("target", 1)])
    await db["outbound_events"].create_index([("org_id", 1), ("seq", 1)], unique=True)
    await db["outbound_events"].create_index("created_at", expireAfterSeconds=30 * 24 * 3600)
    await db["webhook_deliveries"].create_index([("status", 1), ("next_attempt_at", 1)])
    await db["webhook_deliveries"].create_index([("org_id", 1), ("subscription_id", 1), ("created_at", -1)])
    await db["webhook_deliveries"].create_index("created_at", expireAfterSeconds=14 * 24 * 3600)
    await db["webhook_subscriptions"].create_index([("org_id", 1), ("enabled", 1)])
    await db["api_tokens"].create_index("token_hash", unique=True)
    await db["api_tokens"].create_index([("org_id", 1), ("created_at", -1)])
    await db["incident_notes"].create_index([("org_id", 1), ("incident_id", 1), ("created_at", -1)])
    await db["incident_events"].create_index([("org_id", 1), ("incident_id", 1), ("at", -1)])

    runs = db["ingestion_runs"]
    await runs.create_index([("org_id", 1), ("started_at", -1)])
    await runs.create_index("started_at", expireAfterSeconds=RUNS_TTL_SECONDS)
    await db["login_attempts"].create_index("expires_at", expireAfterSeconds=0)

    # Sessions index for quick user-level revocation & expiry
    sessions = db["sessions"]
    await sessions.create_index([("user_id", 1)])
    await sessions.create_index("expires_at", expireAfterSeconds=0)

    # WebSocket single-use tickets TTL
    tickets = db["ws_tickets"]
    await tickets.create_index("expires_at", expireAfterSeconds=0)

    # API rate limits TTL
    rate_limits = db["rate_limits"]
    await rate_limits.create_index("expires_at", expireAfterSeconds=0)
