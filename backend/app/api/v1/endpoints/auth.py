"""
Authentication endpoints: login, refresh, logout.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.schemas.auth import LoginRequest, RefreshRequest, LogoutRequest, TokenResponse
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    TokenError,
)

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


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncIOMotorDatabase = Depends(get_db)):
    """Authenticates a user by email/password and issues an access + refresh token pair."""
    user = await db["users"].find_one({"email": req.email})
    if not user or not user.get("is_active", False) or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

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
