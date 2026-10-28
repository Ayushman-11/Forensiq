"""
Rate limiting service using sliding-window / token-bucket in MongoDB.
Provides decorators and dependencies for throttling expensive operations:
- /search
- /alerts/bulk or batch operations
- /alerts/{id}/investigate
- report / PDF generation
"""

from datetime import datetime, timezone, timedelta
import hashlib
from typing import Optional
from fastapi import HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import db_config
from app.core.config import settings
from app.core.logging import logger


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def rate_limit_key(endpoint: str, identifier: str) -> str:
    """Generates an SHA-256 key for (endpoint, user_or_ip)."""
    return hashlib.sha256(f"{endpoint}|{identifier}".encode()).hexdigest()


async def check_rate_limit(
    db: AsyncIOMotorDatabase,
    key: str,
    max_requests: int,
    window_seconds: int,
) -> Optional[int]:
    """
    Checks and increments rate limit counter.
    Returns 0 if allowed; if limit exceeded, returns seconds until retry.
    """
    now = _now()
    collection = db["rate_limits"]

    # Delete expired window records
    await collection.delete_one({"_id": key, "expires_at": {"$lte": now}})

    doc = await collection.find_one_and_update(
        {"_id": key},
        {
            "$inc": {"count": 1},
            "$setOnInsert": {"expires_at": now + timedelta(seconds=window_seconds)},
        },
        upsert=True,
        return_document=True,
    )

    if doc["count"] <= max_requests:
        return 0

    retry_after = max(1, int((doc["expires_at"] - now).total_seconds()) + 1)
    return retry_after


def rate_limiter(max_requests: int, window_seconds: int, scope: str):
    """
    Dependency factory to rate-limit expensive endpoints per user or client IP.
    """
    async def _dependency(request: Request):
        try:
            if not db_config.client:
                return  # Degrade gracefully if db unavailable

            db = db_config.client[settings.MONGO_DB_NAME]
            
            # Identify user via sub claim from Bearer header if present, else client IP
            auth_header = request.headers.get("authorization", "")
            client_id = request.client.host if request.client else "unknown"
            if auth_header.startswith("Bearer "):
                # Use raw token segment or IP
                client_id = auth_header[7:].strip()[:32]

            key = rate_limit_key(scope, client_id)
            retry_after = await check_rate_limit(db, key, max_requests, window_seconds)

            if retry_after:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for {scope}. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )
        except HTTPException:
            raise
        except Exception as exc:
            # Degrade gracefully: rate limiter failures must never crash application requests
            logger.warning("rate_limiter_unavailable", error=str(exc))
            return

    return _dependency

