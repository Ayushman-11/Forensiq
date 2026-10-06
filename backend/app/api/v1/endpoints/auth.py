"""
Authentication endpoints: login, refresh, logout.
"""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.schemas.auth import LoginRequest, RefreshRequest, LogoutRequest, TokenResponse
from app.core.security import (
    verify_password,
    hash_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    TokenError,
)

from app.services.login_throttle import clear_failures, reserve_attempt, throttle_key

router = APIRouter()


async def _issue_tokens(db: AsyncIOMotorDatabase, user_id: str, email: str, role: str) -> TokenResponse:
    access_token = create_access_token(user_id=user_id, email=email, role=role)
    refresh_token, jti, expires_at = create_refresh_token(user_id=user_id)
    await db["sessions"].insert_one({
        "_id": jti,
        "user_id": user_id,
        "expires_at": expires_at,
    })
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


# Valid bcrypt hash so unknown emails cost the same as a real verification.
_DUMMY_HASH = hash_password("forensiq-dummy-password-for-timing")


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Authenticates a user by email/password and issues an access + refresh token pair."""
    email = req.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    key = throttle_key(email, ip)

    retry_after = await reserve_attempt(db, key)
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = await db["users"].find_one({"email": email})
    hash_to_check = user["password_hash"] if user else _DUMMY_HASH
    # bcrypt is CPU-bound (~250 ms): keep it off the event loop. Exactly one verification per attempt.
    password_ok = await asyncio.to_thread(verify_password, req.password, hash_to_check)
    if not user or not user.get("is_active", False) or not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    await clear_failures(db, key)
    return await _issue_tokens(db, user_id=str(user["_id"]), email=user["email"], role=user["role"])


@router.post("/refresh", response_model=TokenResponse)
async def refresh(req: RefreshRequest, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Rotates a refresh token: validates it, revokes it, and issues a fresh pair."""
    try:
        payload = decode_token(req.refresh_token)
    except TokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    session = await db["sessions"].find_one_and_delete({"_id": payload.get("jti")})
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")

    user = await db["users"].find_one({"_id": payload.get("sub")})
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return await _issue_tokens(db, user_id=str(user["_id"]), email=user["email"], role=user["role"])


@router.post("/logout")
async def logout(req: LogoutRequest, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Revokes a refresh token, ending that session. Idempotent."""
    try:
        payload = decode_token(req.refresh_token)
        await db["sessions"].delete_one({"_id": payload.get("jti")})
    except TokenError:
        pass
    return {"status": "logged_out"}
