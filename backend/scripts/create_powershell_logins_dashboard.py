"""
Deploy a dedicated Splunk Dashboard for PowerShell Executions & Admin Account Activity via REST API.
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.infrastructure.siem.splunk import SplunkClient
from app.core.logging import setup_logging

DASHBOARD_NAME = "forensiq_powershell_and_logins"
DASHBOARD_LABEL = "Forensiq — PowerShell & Admin Activity Monitor"

# Splunk Dashboard XML Definition
POWERSHELL_LOGINS_DASHBOARD_XML = """<dashboard version="1.1">
  <label>Forensiq — PowerShell &amp; Admin Activity Monitor</label>
  <description>Threat Monitoring Dashboard for PowerShell Commands and Admin Account Activity</description>
  <row>
    <panel>
      <table>
        <title>PowerShell Executions &amp; Encoded Commands (Sysmon EventCode 1)</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe" NOT Image="*splunk-powershell.exe" | table _time host User CommandLine ParentImage | sort - _time | head 25</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Admin &amp; User Account Enumeration Activity</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (CommandLine="*net user*" OR CommandLine="*whoami*" OR CommandLine="*net localgroup*") | table _time host User Image CommandLine ParentImage | sort - _time | head 25</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
    <panel>
      <chart>
        <title>Executions by User Account</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count by User | sort - count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Recent System &amp; Discovery Executions</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*systeminfo.exe" OR Image="*cmd.exe") | table _time host User Image CommandLine | sort - _time | head 20</query>
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

        print(f"2. Creating/Deploying '{DASHBOARD_NAME}' Dashboard to Splunk...")
        await client.create_dashboard(
            name=DASHBOARD_NAME,
            label=DASHBOARD_LABEL,
            xml_definition=POWERSHELL_LOGINS_DASHBOARD_XML,
        )
        print(f"   [OK] Dashboard '{DASHBOARD_NAME}' deployed successfully!\n")

        print("3. Fetching latest PowerShell Execution telemetry through SplunkClient...")
        events = await client.search(
            query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"',
            earliest_time="-24h",
            limit=5
        )
        print(f"   [OK] Retrieved {len(events)} normalized PowerShell events:\n")
        for idx, ev in enumerate(events, 1):
            print(f"      [{idx}] Time: {ev.timestamp} | Host: {ev.hostname} | User: {ev.user}")
            print(f"          Cmd: {ev.command_line}\n")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
