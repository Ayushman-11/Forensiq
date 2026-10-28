"""MongoDB index definitions, created idempotently at startup."""

from __future__ import annotations

RUNS_TTL_SECONDS = 30 * 24 * 3600
WS_TICKETS_TTL_SECONDS = 120  # Expire unconsumed tickets after 2 minutes


async def ensure_indexes(db) -> None:
    alerts = db["alerts"]
    await alerts.create_index([("org_id", 1), ("created_at", -1)])
    await alerts.create_index("host")
    await alerts.create_index("user")
    await alerts.create_index("extracted_iocs")
    await alerts.create_index("status")

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
