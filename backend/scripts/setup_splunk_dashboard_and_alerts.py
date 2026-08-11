"""
Script to automatically build a Splunk Dashboard & create Threat Alerts via REST API.
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.infrastructure.siem.splunk import SplunkClient
from app.core.logging import setup_logging, logger

# Splunk Dashboard XML Definition
SOC_DASHBOARD_XML = """<dashboard version="1.1">
  <label>Forensiq — SOC Telemetry &amp; Investigation Overview</label>
  <description>Real-time Sysmon Telemetry &amp; Threat Hunting Dashboard created by Forensiq Backend</description>
  <row>
    <panel>
      <chart>
        <title>Sysmon Events by Event Code (24h)</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by EventCode | sort - count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Top Executed Process Images (Sysmon EventCode 1)</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count by Image | sort - count | head 10</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Suspicious Process &amp; Script Executions</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*reg.exe" OR Image="*schtasks.exe") | table _time host User Image CommandLine ParentImage | sort - _time | head 20</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>"""


async def main():
    setup_logging()
    client = SplunkClient()

    try:
        print("1. Authenticating with Splunk REST API...")
        await client.authenticate()
        print("   [OK] Authenticated successfully as user 'Ayushman'!\n")

        print("2. Creating/Deploying 'forensiq_soc_overview' Dashboard to Splunk...")
        await client.create_dashboard(
            name="forensiq_soc_overview",
            label="Forensiq - SOC Telemetry & Investigation Overview",
            xml_definition=SOC_DASHBOARD_XML,
        )
        print("   [OK] Dashboard 'forensiq_soc_overview' deployed successfully!\n")

        print("3. Creating Saved Searches & Detection Rules in Splunk...")
        
        # Saved Search 1: PowerShell Execution Alert
        await client.create_saved_search(
            name="Forensiq_Alert_PowerShell_Execution",
            search_query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"',
            earliest_time="-24h",
            latest_time="now",
        )
        print("   [OK] Saved Search 'Forensiq_Alert_PowerShell_Execution' created!")

        # Saved Search 2: Registry Modification Alert
        await client.create_saved_search(
            name="Forensiq_Alert_Registry_Modification",
            search_query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*CurrentVersion\\\\Run*"',
            earliest_time="-24h",
            latest_time="now",
        )
        print("   [OK] Saved Search 'Forensiq_Alert_Registry_Modification' created!")

        # Saved Search 3: Network Recon Alert
        await client.create_saved_search(
            name="Forensiq_Alert_Network_Reconnaissance",
            search_query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*net.exe" OR Image="*systeminfo.exe" OR Image="*whoami.exe")',
            earliest_time="-24h",
            latest_time="now",
        )
        print("   [OK] Saved Search 'Forensiq_Alert_Network_Reconnaissance' created!\n")

        print("4. Fetching Triggered Alerts & Saved Searches from Splunk...")
        alerts = await client.list_alerts(limit=10)
        print(f"   [OK] Retrieved {len(alerts)} alerts/saved searches from Splunk!")
        for idx, alert in enumerate(alerts, 1):
            print(f"      [{idx}] Title: {alert.title}")
            print(f"          Severity: {alert.severity} | SIEM: {alert.source_siem}")
            print(f"          ID:       {alert.alert_id[:70]}...\n")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
