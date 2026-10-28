import asyncio
import httpx
import uuid
import json
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime

async def test_extraction():
    # Connect to Mongo
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["forensiq"]
    
    alert_id = str(uuid.uuid4())
    
    # Mock a Fired Alert payload exactly as it would come from Splunk
    fired_alert = {
        "_id": alert_id,
        "title": "[CRITICAL] Suspicious PowerShell Execution & Cradles",
        "severity": "critical",
        "host": "WKSTN-TEST",
        "user": "ayushman",
        "ai_confidence": 0,
        "status": "New",
        "created_at": datetime.utcnow(),
        "source_siem": "splunk",
        "raw_alert_data": {
            "name": "Fired Alert 123",
            "content": {
                "src_ip": "10.0.0.5",
                "dest_ip": "185.15.11.11",
                "domain": "malicious-c2.com",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc JABzAD0A..."
            }
        }
    }
    
    # Insert into DB
    await db.alerts.insert_one(fired_alert)
    print(f"Inserted Mock Fired Alert: {alert_id}")
    
    # Trigger Investigate Pipeline
    encoded_id = urllib.parse.quote(alert_id, safe='')
    url = f"http://localhost:8001/api/v1/alerts/{encoded_id}/investigate"
    
    async with httpx.AsyncClient(timeout=30.0) as http_client:
        print(f"Executing LangGraph pipeline via {url} ...")
        response = await http_client.post(url)
        
        if response.status_code == 200:
            print("\n--- Pipeline Success ---")
            print("API Response:", response.json())
            
            # Fetch updated doc
            updated_alert = await db.alerts.find_one({"_id": alert_id})
            print("\nExtracted IOCs stored in DB:")
            print(json.dumps(updated_alert.get("extracted_iocs", []), indent=2))
            
            print("\nVirusTotal / Enrichment Results stored in DB:")
            print(json.dumps(updated_alert.get("enrichments", []), indent=2))
            
            print("\nAI Confidence Updated to:", updated_alert.get("ai_confidence"))
        else:
            print("Failed!", response.status_code, response.text)

if __name__ == "__main__":
    asyncio.run(test_extraction())
