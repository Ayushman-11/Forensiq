"""MongoDB index definitions, created idempotently at startup."""

from __future__ import annotations

RUNS_TTL_SECONDS = 30 * 24 * 3600


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
