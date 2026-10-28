"""
Script to trigger Splunk Saved Searches and fetch fired alerts into Forensiq.
"""

import asyncio
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.infrastructure.siem.splunk import SplunkClient
from app.core.logging import setup_logging

SAVED_SEARCHES = [
    "Forensiq_Alert_PowerShell_Execution",
    "Forensiq_Alert_Registry_Modification",
    "Forensiq_Alert_Network_Reconnaissance",
]


async def main():
    setup_logging()
    client = SplunkClient()

    try:
        print("1. Authenticating with Splunk REST API...")
        await client.authenticate()
        print("   [OK] Authenticated successfully as user 'Ayushman'!\n")

        print("2. Dispatching & Triggering Saved Searches in Splunk...")
        for rule_name in SAVED_SEARCHES:
            try:
                sid = await client.trigger_saved_search(rule_name)
                print(f"   [OK] Triggered search '{rule_name}' (SID: {sid})")
            except Exception as e:
                print(f"   [WARN] Could not trigger '{rule_name}': {e}")

        print("\n3. Waiting 3 seconds for Splunk to process alert dispatches...")
        await asyncio.sleep(3)

        print("\n4. Querying Splunk Fired Alerts API (/services/alerts/fired_alerts)...")
        alerts = await client.list_alerts(limit=10)
        print(f"   [OK] Total Fired Alerts Retrieved: {len(alerts)}\n")

        for idx, alert in enumerate(alerts, 1):
            print(f"   Alert [{idx}]:")
            print(f"      Title:        {alert.title}")
            print(f"      Severity:     {alert.severity}")
            print(f"      SIEM Source:  {alert.source_siem}")
            print(f"      Alert ID:     {alert.alert_id}")
            print("-" * 60)

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
