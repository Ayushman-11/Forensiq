"""
CLI script to bootstrap the first admin user in MongoDB.

Usage:
    cd backend
    ./venv/Scripts/python.exe scripts/create_admin_user.py --email admin@forensiq.ai --password "change-me"
"""

import argparse
import asyncio
import sys
import uuid

from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, ".")  # allow `python scripts/create_admin_user.py` from backend/

from app.core.config import settings
from app.core.security import hash_password


async def create_admin(email: str, password: str, role: str) -> None:
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.MONGO_DB_NAME]
    email = email.strip().lower()

    existing = await db["users"].find_one({"email": email})
    if existing:
        await db["users"].update_one(
            {"_id": existing["_id"]},
            {"$set": {"password_hash": hash_password(password), "role": role, "is_active": True}}
        )
        print(f"Updated password for existing user '{email}' (id={existing['_id']}).")
        client.close()
        return

    user_id = str(uuid.uuid4())
    await db["users"].insert_one({
        "_id": user_id,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "is_active": True,
    })
    print(f"Created user '{email}' with role '{role}' (id={user_id}).")
    client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap a Forensiq user.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--role", default="admin", choices=["admin", "soc_manager", "soc_analyst"]
    )
    args = parser.parse_args()
    asyncio.run(create_admin(args.email, args.password, args.role))


if __name__ == "__main__":
    main()
