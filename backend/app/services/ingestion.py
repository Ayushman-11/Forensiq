import uuid
from typing import List
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.infrastructure.siem.splunk import SplunkClient
from app.core.logging import logger
from app.schemas.normalized_event import NormalizedAlert

class IngestionService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.splunk = SplunkClient()
        
    async def fetch_and_store_alerts(self, limit: int = 50) -> int:
        """
        Fetches alerts from Splunk and stores them in MongoDB.
        Avoids duplicates by checking alert_id.
        """
        inserted_count = 0
        try:
            alerts: List[NormalizedAlert] = await self.splunk.list_alerts(limit=limit)
            
            for alert in alerts:
                # Convert Pydantic model to dict
                alert_data = alert.model_dump()
                # Use alert_id as _id if possible, or generate one
                alert_id = alert_data.pop("alert_id", str(uuid.uuid4()))
                
                # Check if it already exists to avoid duplicates
                existing = await self.db["alerts"].find_one({"_id": alert_id})
                if not existing:
                    alert_data["_id"] = alert_id
                    # Map fields to match AlertModel for UI
                    # Title is already there. Severity is there.
                    # Try to extract host and user from raw data
                    raw = alert_data.get("raw_alert_data", {})
                    content = raw.get("content", {}) if isinstance(raw, dict) else {}
                    
                    host = alert_data.get("affected_hostname") or content.get("host") or "Unknown"
                    user = alert_data.get("affected_user") or content.get("user") or "Unknown"
                    
                    alert_data["host"] = host
                    alert_data["user"] = user
                    alert_data["ai_confidence"] = 0 # Will be populated by agents later
                    alert_data["status"] = "New"
                    
                    await self.db["alerts"].insert_one(alert_data)
                    inserted_count += 1
            
            logger.info("splunk_ingestion_complete", fetched=len(alerts), inserted=inserted_count)
            return inserted_count
            
        except Exception as e:
            logger.error("splunk_ingestion_failed", error=str(e))
            raise e
        finally:
            await self.splunk.close()
