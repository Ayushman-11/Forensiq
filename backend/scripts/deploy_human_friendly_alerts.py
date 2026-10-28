"""
Deploy User-Friendly Threat Alerts Hub Dashboard and Clean Saved Search Alert Rules in Splunk.
"""

import asyncio
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.infrastructure.siem.splunk import SplunkClient
from app.core.logging import setup_logging

DASHBOARD_NAME = "forensiq_threat_alerts_hub"
DASHBOARD_LABEL = "Forensiq — SOC Incident & Threat Alerts Hub"

# Clean, modern, analyst-friendly XML dashboard definition
ALERT_HUB_DASHBOARD_XML = """<dashboard version="1.1">
  <label>Forensiq — SOC Incident &amp; Threat Alerts Hub</label>
  <description>User-friendly SOC Analyst Investigation Hub: Real-time Threat Alerts &amp; MITRE ATT&amp;CK Mapping</description>
  <row>
    <panel>
      <single>
        <title>Total Critical &amp; High Severity Alerts (24h)</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*powershell.exe" OR TargetObject="*CurrentVersion\\\\Run*") NOT Image="*splunk-powershell.exe" | stats count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="underLabel">Active Threats Requiring Analyst Triage</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>🚨 Active Security Threats &amp; MITRE ATT&amp;CK Mappings</title>
        <search>
          <query>index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 NOT Image="*splunk-powershell.exe"
| eval Severity=case(
    match(Image, "(?i)powershell\.exe"), "CRITICAL",
    match(TargetObject, "(?i)CurrentVersion\\\\Run"), "HIGH",
    match(CommandLine, "(?i)(net user|whoami|systeminfo)"), "MEDIUM",
    1=1, "INFORMATIONAL"
  )
| eval MITRE_Technique=case(
    match(Image, "(?i)powershell\.exe"), "T1059.001 - Command and Scripting Interpreter: PowerShell",
    match(TargetObject, "(?i)CurrentVersion\\\\Run"), "T1547.001 - Boot/Logon Autostart Execution: Registry Run Keys",
    match(CommandLine, "(?i)(net user|whoami|systeminfo)"), "T1082 / T1087 - System &amp; Account Discovery",
    1=1, "T1059 - Command Execution"
  )
| where Severity!="INFORMATIONAL"
| table _time Severity MITRE_Technique host User CommandLine
| sort - _time
| head 25</query>
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

        print("2. Deploying 'forensiq_threat_alerts_hub' User-Friendly Dashboard to Splunk...")
        await client.create_dashboard(
            name=DASHBOARD_NAME,
            label=DASHBOARD_LABEL,
            xml_definition=ALERT_HUB_DASHBOARD_XML,
        )
        print("   [OK] User-friendly Dashboard 'forensiq_threat_alerts_hub' deployed!\n")

        print("3. Registering Human-Readable Alert Rules in Splunk...")
        
        # Rule 1: Critical PowerShell Execution
        await client.create_saved_search(
            name="Forensiq_Alert_PowerShell_Execution",
            search_query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe" NOT Image="*splunk-powershell.exe"',
            earliest_time="-24h",
            latest_time="now",
        )
        print("   [OK] Created Rule: [CRITICAL] Suspicious PowerShell & Script Execution")

        # Rule 2: Persistence Registry
        await client.create_saved_search(
            name="Forensiq_Alert_Registry_Modification",
            search_query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*CurrentVersion\\\\Run*"',
            earliest_time="-24h",
            latest_time="now",
        )
        print("   [OK] Created Rule: [HIGH] Persistence via Registry Run Keys")

        # Rule 3: Discovery
        await client.create_saved_search(
            name="Forensiq_Alert_Network_Reconnaissance",
            search_query='source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*net.exe" OR Image="*systeminfo.exe" OR Image="*whoami.exe")',
            earliest_time="-24h",
            latest_time="now",
        )
        print("   [OK] Created Rule: [MEDIUM] System & Account Discovery Reconnaissance\n")

        print("4. Fetching Normalized Human-Friendly Alerts from Forensiq Backend...")
        alerts = await client.list_alerts(limit=10)
        print(f"   [OK] Total Enriched Alerts: {len(alerts)}\n")

        for idx, alert in enumerate(alerts, 1):
            print(f"   Alert [{idx}]:")
            print(f"      Title:      {alert.title}")
            print(f"      Severity:   {alert.severity.upper()}")
            print(f"      Summary:    {alert.description}")
            print(f"      MITRE:      {', '.join(alert.mitre_techniques)}")
            print("-" * 65)

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
