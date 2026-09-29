import asyncio
import httpx
from motor.motor_asyncio import AsyncIOMotorClient

async def test_pipeline():
    # 1. Connect to MongoDB and find a real Splunk alert
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["forensiq"]
    
    # Splunk alerts usually have a 'raw_alert_data' field, seeded ones do not
    alert = await db.alerts.find_one({"raw_alert_data": {"$exists": True}})
    
    if not alert:
        print("No Splunk alerts found in the database. Trying to ingest...")
        async with httpx.AsyncClient() as http_client:
            res = await http_client.post("http://localhost:8001/api/v1/alerts/ingest")
            print("Ingestion result:", res.json())
            alert = await db.alerts.find_one({"raw_alert_data": {"$exists": True}})
            
    if not alert:
        print("Still no Splunk alerts found. Cannot test pipeline on real Splunk data.")
        return
        
    alert_id = alert["_id"]
    print(f"Testing pipeline on Alert ID: {alert_id}")
    print(f"Title: {alert.get('title')}")
    import json
    with open("raw_alert.json", "w") as f:
        json.dump(alert.get('raw_alert_data', {}), f, indent=2)
    print("Saved raw splunk data to raw_alert.json")
    
    # 2. Trigger the investigate endpoint
    import urllib.parse
    encoded_id = urllib.parse.quote(alert_id, safe='')
    url = f"http://localhost:8001/api/v1/alerts/{encoded_id}/investigate"
    async with httpx.AsyncClient(timeout=30.0) as http_client:
        response = await http_client.post(url)
        
        if response.status_code == 200:
            print("Pipeline executed successfully!")
            print("Response:", response.json())
            
            # Fetch the updated alert to see the enrichments
            updated_alert = await db.alerts.find_one({"_id": alert_id})
            print("\nExtracted IOCs in DB:")
            print(updated_alert.get("extracted_iocs"))
            print("\nEnrichments in DB:")
            print(updated_alert.get("enrichments"))
            print("\nAI Confidence:", updated_alert.get("ai_confidence"))
        else:
            print(f"Pipeline execution failed! Status: {response.status_code}")
            print(response.text)

if __name__ == "__main__":
    asyncio.run(test_pipeline())
