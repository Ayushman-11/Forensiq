"""
Directory of users in the caller's organisation, for assignment pickers.
"""

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.core.tenancy import scoped_query
from app.database.session import get_db

router = APIRouter()


@router.get("")
async def list_users(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Active users in the caller's tenant. Never returns password hashes."""
    users = []
    cursor = db["users"].find(scoped_query(user, {"is_active": True}), {"email": 1, "role": 1}).sort("email", 1)
    async for doc in cursor:
        users.append({"id": str(doc["_id"]), "email": doc.get("email"), "role": doc.get("role")})
    return users
