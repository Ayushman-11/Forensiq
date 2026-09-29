"""
Forensiq: End-to-end pipeline test
1. Checks backend health
2. Ingests fired alerts from Splunk into MongoDB
3. Lists alerts
4. Runs investigation pipeline on first alert
5. Shows dashboard metrics
"""
import asyncio
import json
import urllib.parse
import httpx

BASE = "http://localhost:8001/api/v1"

async def test():
    print("=" * 60)
    print("  Forensiq Pipeline Test")
    print("=" * 60)

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        # 1. Health
        print("\n[1/5] Health check...")
        try:
            r = await client.get(f"{BASE}/health/")
            print(f"  Status: {r.json()}")
        except Exception as e:
            print(f"  Backend not running on port 8001: {e}")
            return

        # 2. Ingest from Splunk
        print("\n[2/5] Ingesting alerts from Splunk...")
        r = await client.post(f"{BASE}/alerts/ingest")
        result = r.json()
        print(f"  Result: {json.dumps(result, indent=2)}")

        # 3. List alerts
        print("\n[3/5] Listing alerts in MongoDB...")
        r = await client.get(f"{BASE}/alerts/")
        alerts = r.json()
        print(f"  Total alerts: {len(alerts)}")
        for a in alerts[:5]:
            sev = a.get("severity", "?")
            title = a.get("title", "?")
            host = a.get("host", "?")
            print(f"    - [{sev}] {title} (host={host})")

        # 4. Investigate first alert
        if alerts:
            alert_id = alerts[0].get("id") or alerts[0].get("_id")
            print(f"\n[4/5] Investigating alert: {alert_id}")
            encoded = urllib.parse.quote(str(alert_id), safe="")
            r = await client.post(f"{BASE}/alerts/{encoded}/investigate", timeout=30.0)
            if r.status_code == 200:
                inv = r.json()
                print(f"  Pipeline result: {json.dumps(inv, indent=2)}")
            else:
                print(f"  Investigation failed: {r.status_code} {r.text}")
        else:
            print("\n[4/5] No alerts to investigate")

        # 5. Dashboard metrics
        print("\n[5/5] Dashboard metrics...")
        r = await client.get(f"{BASE}/dashboard/metrics")
        print(f"  Metrics: {json.dumps(r.json(), indent=2)}")

    print("\n" + "=" * 60)
    print("  Pipeline Test Complete!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test())
