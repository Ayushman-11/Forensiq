"""
Forensiq: Create Splunk Dashboard + Alert Rules + Test Pipeline
Connects directly to Splunk REST API to create:
  1. A Forensiq SOC Dashboard
  2. Saved Search alert rules for detection
  3. Triggers the alerts and tests the full Forensiq ingestion pipeline
"""

import asyncio
import sys
import os

# Add the backend to path
sys.path.insert(0, os.path.dirname(__file__))

from app.infrastructure.siem.splunk import SplunkClient
from app.core.config import settings


# ─────────────────────────────────────────────────
# 1. DASHBOARD XML
# ─────────────────────────────────────────────────
DASHBOARD_XML = """<dashboard version="1.1" theme="dark">
  <label>Forensiq SOC Dashboard</label>
  <description>Real-time security monitoring powered by Forensiq AI Investigation Platform</description>

  <row>
    <panel>
      <title>Total Security Events (Last 30m)</title>
      <single>
        <search>
          <query>index=windows earliest=-30m | stats count</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="rangeValues">[0,100,500,1000]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <title>Event Sources</title>
      <chart>
        <search>
          <query>index=windows earliest=-30m | stats count by source | sort -count</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.showPercent">1</option>
      </chart>
    </panel>
    <panel>
      <title>Events by EventCode</title>
      <chart>
        <search>
          <query>index=windows source="XmlWinEventLog:Security" earliest=-30m | stats count by EventCode | sort -count | head 10</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">all</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Security Event Timeline</title>
      <chart>
        <search>
          <query>index=windows earliest=-30m | timechart span=1m count by source</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.nullValueMode">zero</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Sysmon: Process Creation (EventID 1)</title>
      <table>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-30m
| table _time, User, Image, CommandLine, ParentImage
| sort -_time
| head 20</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="count">10</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Sysmon: Network Connections (EventID 3)</title>
      <table>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-30m
| table _time, User, Image, DestinationIp, DestinationPort, Protocol
| sort -_time
| head 20</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="count">10</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Security: Logon Events (4624)</title>
      <table>
        <search>
          <query>index=windows source="XmlWinEventLog:Security" EventCode=4624 earliest=-30m
| table _time, Account_Name, Logon_Type, Source_Network_Address
| sort -_time</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="count">10</option>
      </table>
    </panel>
    <panel>
      <title>Security: Credential Operations (5058/5061)</title>
      <chart>
        <search>
          <query>index=windows source="XmlWinEventLog:Security" (EventCode=5058 OR EventCode=5061) earliest=-30m
| timechart span=5m count by EventCode</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>PowerShell Activity</title>
      <table>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" earliest=-30m
| table _time, EventCode, Computer, Message
| sort -_time
| head 15</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="count">10</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Top Processes by Execution Count</title>
      <chart>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-30m
| stats count by Image
| sort -count
| head 15</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">all</option>
      </chart>
    </panel>
    <panel>
      <title>Reconnaissance Commands</title>
      <table>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-60m
(Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\arp.exe" OR Image="*\\ping.exe" 
 OR Image="*\\ipconfig.exe" OR Image="*\\systeminfo.exe" OR Image="*\\whoami.exe" 
 OR Image="*\\nmap.exe" OR Image="*\\nltest.exe" OR Image="*\\nslookup.exe")
| table _time, User, Image, CommandLine
| sort -_time</query>
          <earliest>-60m</earliest>
          <latest>now</latest>
        </search>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
</dashboard>"""


# ─────────────────────────────────────────────────
# 2. ALERT RULES (Saved Searches)
# ─────────────────────────────────────────────────
ALERT_RULES = [
    {
        "name": "Forensiq_Alert_Port_Scan_Detection",
        "query": (
            'index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-5m '
            '| stats dc(DestinationPort) as unique_ports by Image, SourceIp '
            '| where unique_ports > 10'
        ),
        "description": "Detects port scanning - process connecting to many unique ports",
    },
    {
        "name": "Forensiq_Alert_Host_Discovery_Sweep",
        "query": (
            'index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-5m '
            '(Image="*\\\\ping.exe" OR Image="*\\\\arp.exe" OR Image="*\\\\net.exe") '
            '| stats count by Image, User '
            '| where count > 3'
        ),
        "description": "Detects host discovery via ping sweep, arp, or net view commands",
    },
    {
        "name": "Forensiq_Alert_Suspicious_PowerShell",
        "query": (
            'index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-5m '
            'Image="*\\\\powershell.exe" '
            '(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*Invoke-*" '
            'OR CommandLine="*IEX*" OR CommandLine="*downloadstring*" OR CommandLine="*bypass*") '
            '| table _time, User, CommandLine'
        ),
        "description": "Detects suspicious PowerShell execution patterns (encoded, download cradles)",
    },
    {
        "name": "Forensiq_Alert_Reconnaissance_Commands",
        "query": (
            'index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-5m '
            '(Image="*\\\\whoami.exe" OR Image="*\\\\systeminfo.exe" OR Image="*\\\\ipconfig.exe" '
            'OR Image="*\\\\nltest.exe" OR Image="*\\\\net.exe") '
            '| stats dc(Image) as unique_tools count by User '
            '| where unique_tools >= 3'
        ),
        "description": "Multiple reconnaissance tools run by same user within 5 minutes",
    },
    {
        "name": "Forensiq_Alert_Brute_Force_Authentication",
        "query": (
            'index=windows source="XmlWinEventLog:Security" EventCode=4625 earliest=-5m '
            '| stats count by Account_Name, Source_Network_Address '
            '| where count > 3'
        ),
        "description": "Multiple failed login attempts from same source (brute force indicator)",
    },
    {
        "name": "Forensiq_Alert_Network_Connection_Anomaly",
        "query": (
            'index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-5m '
            '| stats dc(DestinationIp) as unique_dests count by Image, User '
            '| where unique_dests > 5'
        ),
        "description": "Process connecting to unusually many unique destination IPs",
    },
]


async def main():
    print("=" * 60)
    print("  Forensiq: Splunk Dashboard + Alert Rules Setup")
    print("=" * 60)

    splunk = SplunkClient()

    # ── Step 1: Authenticate ──
    print("\n[1/4] Authenticating with Splunk...")
    await splunk.authenticate()
    print(f"  ✓ Authenticated as '{splunk.username}'")

    # ── Step 2: Create Dashboard ──
    print("\n[2/4] Creating Forensiq SOC Dashboard...")
    try:
        await splunk.create_dashboard(
            name="forensiq_soc_dashboard",
            label="Forensiq SOC Dashboard",
            xml_definition=DASHBOARD_XML,
        )
        print("  ✓ Dashboard created: http://localhost:8000/en-US/app/search/forensiq_soc_dashboard")
    except Exception as e:
        print(f"  ✗ Dashboard error: {e}")

    # ── Step 3: Create Alert Rules ──
    print(f"\n[3/4] Creating {len(ALERT_RULES)} alert rules...")
    for rule in ALERT_RULES:
        try:
            await splunk.create_saved_search(
                name=rule["name"],
                search_query=rule["query"],
                earliest_time="-5m",
                latest_time="now",
                cron_schedule="*/5 * * * *",
            )
            print(f"  ✓ {rule['name']}")
        except Exception as e:
            print(f"  ✗ {rule['name']}: {e}")

    # ── Step 4: Trigger all alerts to generate fired alerts ──
    print("\n[4/4] Triggering alert rules to generate fired alerts...")
    for rule in ALERT_RULES:
        try:
            sid = await splunk.trigger_saved_search(rule["name"])
            print(f"  ✓ Triggered {rule['name']} (SID: {sid})")
        except Exception as e:
            print(f"  ✗ {rule['name']}: {e}")

    await splunk.close()

    print("\n" + "=" * 60)
    print("  Setup Complete!")
    print("=" * 60)
    print(f"""
Next Steps:
  1. View Dashboard: http://localhost:8000/en-US/app/search/forensiq_soc_dashboard
  2. View Alerts:    http://localhost:8000/en-US/app/search/alerts
  3. Test Pipeline:  python test_agents.py
    """)


if __name__ == "__main__":
    asyncio.run(main())
