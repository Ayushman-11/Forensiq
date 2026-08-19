"""
FastAPI Route Dependencies.
Provides Dependency Injection for SIEM Clients, Database Sessions, and Auth.
"""

from typing import AsyncGenerator, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.infrastructure.siem.splunk import SplunkClient
from app.infrastructure.siem.base import SIEMProvider
from app.core.security import decode_token, TokenError
from app.database.session import get_db

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_siem_client() -> AsyncGenerator[SIEMProvider, None]:
    """Dependency Provider for SIEM Client (SplunkClient). Ensures client is closed after request."""
    client = SplunkClient()
    try:
        yield client
    finally:
        await client.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> dict:
    """
    Validates the Authorization: Bearer <access_token> header and returns
    the corresponding user document (password_hash stripped).
    Raises 401 if the token is missing, invalid, expired, or the user
    no longer exists / is inactive.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user = await db["users"].find_one({"_id": payload.get("sub")})
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    user["id"] = str(user.pop("_id"))
    user.pop("password_hash", None)
    return user


def require_roles(*roles: str) -> Callable:
    """Dependency factory: raises 403 unless current_user's role is in `roles`."""

    async def _check(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(roles)}",
            )
        return user

    return _check
