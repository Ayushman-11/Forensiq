"""
MongoDB Async Database Client Provider.
"""

from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

class DatabaseConfig:
    client: AsyncIOMotorClient = None

db_config = DatabaseConfig()

async def connect_to_mongo():
    """Create database connection."""
    db_config.client = AsyncIOMotorClient(settings.MONGO_URI)

async def close_mongo_connection():
    """Close database connection."""
    if db_config.client:
        db_config.client.close()

async def get_db():
    """FastAPI Dependency for yielding MongoDB database."""
    if not db_config.client:
        # Fallback just in case it wasn't initialized in lifespan
        db_config.client = AsyncIOMotorClient(settings.MONGO_URI)
    return db_config.client[settings.MONGO_DB_NAME]
