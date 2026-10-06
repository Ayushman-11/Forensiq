"""Safe error responses: log the real error server-side, return only a reference id."""

import uuid

from fastapi import HTTPException

from app.core.logging import logger


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def internal_error(event: str, exc: Exception, **context) -> HTTPException:
    """Log `exc` with a fresh reference id and return a generic 500 for the caller to raise."""
    ref = new_request_id()
    logger.error(event, request_id=ref, error=str(exc), error_type=type(exc).__name__, **context)
    return HTTPException(status_code=500, detail=f"Internal server error (ref {ref})")
