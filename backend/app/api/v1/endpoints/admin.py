"""
Admin User Management endpoints.
Restricted to 'admin' role. Supports listing users, inviting/creating users,
toggling active status, resetting passwords, and terminating active sessions.
"""

from datetime import datetime, timezone
from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.api.deps import require_roles
from app.core.security import hash_password
from app.core.tenancy import scoped_query, tenant_id
from app.schemas.auth import (
    UserOut,
    CreateUserRequest,
    UpdateUserStatusRequest,
    ResetPasswordRequest,
)

router = APIRouter()
admin_required = require_roles("admin")


@router.get("/users", response_model=List[UserOut])
async def list_users(
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Lists all users belonging to the admin's organization."""
    org = tenant_id(admin_user)
    query = scoped_query({}, org)
    cursor = db["users"].find(query).sort("created_at", -1)
    users = []
    async for doc in cursor:
        users.append(
            UserOut(
                id=str(doc["_id"]),
                email=doc["email"],
                role=doc.get("role", "analyst"),
                is_active=doc.get("is_active", True),
                mfa_enabled=doc.get("mfa_enabled", False),
                created_at=doc.get("created_at"),
            )
        )
    return users


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    req: CreateUserRequest,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Creates a new analyst/admin account."""
    org = tenant_id(admin_user)
    email = req.email.strip().lower()

    existing = await db["users"].find_one({"email": email})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    allowed_roles = {"admin", "senior_analyst", "analyst", "viewer"}
    if req.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(sorted(allowed_roles))}",
        )

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(req.password)
    now = datetime.now(timezone.utc).isoformat()

    doc = {
        "_id": user_id,
        "email": email,
        "password_hash": pw_hash,
        "role": req.role,
        "is_active": True,
        "mfa_enabled": False,
        "org_id": org,
        "created_at": now,
        "created_by": admin_user["id"],
    }
    await db["users"].insert_one(doc)

    return UserOut(
        id=user_id,
        email=email,
        role=req.role,
        is_active=True,
        mfa_enabled=False,
        created_at=now,
    )


@router.patch("/users/{user_id}/status", response_model=UserOut)
async def update_user_status(
    user_id: str,
    req: UpdateUserStatusRequest,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Enables or disables a user account. Disabling immediately terminates all user sessions."""
    org = tenant_id(admin_user)
    user = await db["users"].find_one({"_id": user_id, "org_id": org})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["_id"] == admin_user["id"] and not req.is_active:
        raise HTTPException(status_code=400, detail="Cannot disable your own administrator account")

    await db["users"].update_one(
        {"_id": user_id},
        {"$set": {"is_active": req.is_active}},
    )

    if not req.is_active:
        # Revoke all active sessions immediately
        await db["sessions"].delete_many({"user_id": user_id})

    user["is_active"] = req.is_active
    return UserOut(
        id=str(user["_id"]),
        email=user["email"],
        role=user.get("role", "analyst"),
        is_active=user["is_active"],
        mfa_enabled=user.get("mfa_enabled", False),
        created_at=user.get("created_at"),
    )


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: str,
    req: ResetPasswordRequest,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Resets a user's password and forces logout of all existing sessions."""
    org = tenant_id(admin_user)
    user = await db["users"].find_one({"_id": user_id, "org_id": org})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_hash = hash_password(req.password)
    await db["users"].update_one(
        {"_id": user_id},
        {"$set": {"password_hash": new_hash}},
    )
    # Terminate all active sessions so password reset forces re-authentication
    await db["sessions"].delete_many({"user_id": user_id})
    return {"status": "password_reset", "message": "Password updated and all sessions invalidated"}


@router.post("/users/{user_id}/terminate-sessions")
async def terminate_user_sessions(
    user_id: str,
    admin_user: dict = Depends(admin_required),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Force signs out a user across all browsers/devices by revoking all refresh tokens."""
    org = tenant_id(admin_user)
    user = await db["users"].find_one({"_id": user_id, "org_id": org})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    res = await db["sessions"].delete_many({"user_id": user_id})
    return {
        "status": "sessions_terminated",
        "revoked_count": res.deleted_count,
    }

