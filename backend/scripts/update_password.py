import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import sys

sys.path.insert(0, ".")
from app.core.security import hash_password
from app.core.config import settings

async def update_pass():
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.MONGO_DB_NAME]
    res = await db["users"].update_one(
        {"email": "admin@forensiq.ai"},
        {"$set": {"password_hash": hash_password("AdminPassword123!")}}
    )
    print("Updated count:", res.modified_count)
    client.close()

if __name__ == "__main__":
    asyncio.run(update_pass())
