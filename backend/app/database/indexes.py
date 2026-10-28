"""MongoDB index definitions and versioned migrations, executed idempotently at startup."""

from __future__ import annotations

from app.database.migrations import CURRENT_SCHEMA_VERSION, run_migrations

RUNS_TTL_SECONDS = 30 * 24 * 3600


async def ensure_indexes(db) -> None:
    """Delegates index creation and version tracking to the migration engine."""
    await run_migrations(db)
