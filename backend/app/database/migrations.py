"""
Versioned MongoDB Schema Migration Engine.

Tracks applied migrations in the `schema_versions` collection.
Guarantees:
- Idempotent execution
- Forward-only version progression
- Refuses to boot if DB schema is newer than the codebase schema version
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Coroutine, List, Tuple

from app.core.config import settings
from app.core.logging import logger

CURRENT_SCHEMA_VERSION = 2
RUNS_TTL_SECONDS = 30 * 24 * 3600


class SchemaVersionError(RuntimeError):
    """Raised when the database schema version is incompatible with this application code."""
    pass


async def get_current_schema_version(db) -> int:
    """Reads current applied schema version from the schema_versions collection."""
    doc = await db["schema_versions"].find_one({"_id": "current"})
    if not doc:
        return 0
    return int(doc.get("version", 0))


async def set_current_schema_version(db, version: int, description: str) -> None:
    """Records the newly applied schema version and appends to migration history."""
    now = datetime.now(timezone.utc)
    await db["schema_versions"].update_one(
        {"_id": "current"},
        {
            "$set": {"version": version, "updated_at": now},
            "$push": {
                "history": {
                    "version": version,
                    "description": description,
                    "applied_at": now,
                }
            },
        },
        upsert=True,
    )


# --- Migration definitions ---

async def migration_v1_base_indexes(db) -> None:
    """Migration 1: Base indexes for alerts, ingestion, auth and cache."""
    # alerts
    alerts = db["alerts"]
    await alerts.create_index([("org_id", 1), ("created_at", -1)])
    await alerts.create_index("host")
    await alerts.create_index("user")
    await alerts.create_index("extracted_iocs")
    await alerts.create_index("status")

    # ingestion_runs
    runs = db["ingestion_runs"]
    await runs.create_index([("org_id", 1), ("started_at", -1)])
    await runs.create_index("started_at", expireAfterSeconds=RUNS_TTL_SECONDS)

    # login attempts
    await db["login_attempts"].create_index("expires_at", expireAfterSeconds=0)

    # sessions
    await db["sessions"].create_index("expires_at", expireAfterSeconds=0)

    # ioc cache
    await db["ioc_cache"].create_index([("ioc", 1), ("source", 1)], unique=True)
    await db["ioc_cache"].create_index(
        "cached_at", expireAfterSeconds=int(settings.IOC_CACHE_TTL_HOURS * 3600)
    )


async def migration_v2_durability_and_governance(db) -> None:
    """
    Migration 2: Audit log compound indexes + TTL, investigation jobs retention & leasing,
    alert notes TTL, real-time investigation events collection, and policies collection.
    """
    # 1. audit_logs: compound index & TTL retention
    audit = db["audit_logs"]
    await audit.create_index([
        ("org_id", 1),
        ("entity_type", 1),
        ("entity_id", 1),
        ("created_at", -1),
    ])
    audit_ttl_seconds = int(settings.AUDIT_RETENTION_DAYS * 86400)
    await audit.create_index("created_at", expireAfterSeconds=audit_ttl_seconds)

    # 2. investigation_jobs: compound index, status, leasing, and TTL on completed_at
    jobs = db["investigation_jobs"]
    await jobs.create_index([("org_id", 1), ("alert_id", 1), ("created_at", -1)])
    await jobs.create_index("status")
    await jobs.create_index("lease_expires_at")
    job_ttl_seconds = int(settings.INVESTIGATION_JOB_RETENTION_DAYS * 86400)
    await jobs.create_index("completed_at", expireAfterSeconds=job_ttl_seconds)

    # 3. alert_notes: compound index and TTL retention
    notes = db["alert_notes"]
    await notes.create_index([("org_id", 1), ("alert_id", 1), ("created_at", 1)])
    notes_ttl_seconds = int(settings.ALERT_NOTE_RETENTION_DAYS * 86400)
    await notes.create_index("created_at", expireAfterSeconds=notes_ttl_seconds)

    # 4. investigation_events: distributed pub/sub event persistence & 7-day TTL
    events = db["investigation_events"]
    await events.create_index([("alert_id", 1), ("created_at", 1)])
    await events.create_index("created_at", expireAfterSeconds=7 * 86400)

    # 5. policies: governance policy versioning & change history
    policies = db["policies"]
    await policies.create_index([("org_id", 1), ("policy_type", 1), ("version", -1)])


MIGRATIONS: List[Tuple[int, str, Callable[[object], Coroutine]]] = [
    (1, "Base collection indexes and TTLs", migration_v1_base_indexes),
    (2, "Data durability, audit compound index & TTL, job queue & policy indexes", migration_v2_durability_and_governance),
]


async def run_migrations(db) -> int:
    """
    Runs all pending database schema migrations up to CURRENT_SCHEMA_VERSION.
    Fails fast and raises SchemaVersionError if the database is on an unknown newer version.
    """
    db_version = await get_current_schema_version(db)

    if db_version > CURRENT_SCHEMA_VERSION:
        msg = (
            f"Database schema version ({db_version}) is newer than application supported version "
            f"({CURRENT_SCHEMA_VERSION}). Halting startup to prevent data corruption."
        )
        logger.error("schema_version_mismatch", db_version=db_version, app_version=CURRENT_SCHEMA_VERSION)
        raise SchemaVersionError(msg)

    if db_version == CURRENT_SCHEMA_VERSION:
        logger.info("schema_version_up_to_date", version=db_version)
        return db_version

    logger.info("running_schema_migrations", from_version=db_version, target_version=CURRENT_SCHEMA_VERSION)

    for version, description, migration_fn in MIGRATIONS:
        if version > db_version:
            logger.info("applying_schema_migration", version=version, description=description)
            try:
                await migration_fn(db)
                await set_current_schema_version(db, version, description)
            except Exception as exc:
                logger.error("schema_migration_failed", version=version, error=str(exc))
                raise

    final_version = await get_current_schema_version(db)
    logger.info("schema_migrations_completed", current_version=final_version)
    return final_version

