import asyncio
from app.infrastructure.siem.splunk import SplunkClient
from app.core.logging import logger

async def setup():
    client = SplunkClient()
    
    print("Setting up Splunk rules for Forensiq...")
    
    # 1. Port Scanning Rule
    print("Creating Port Scanning Rule...")
    await client.create_saved_search(
        name="Forensiq_Alert_Port_Scanning",
        search_query='search index=* (dest_port=* OR action=blocked) | stats count by src_ip | where count > 100',
        cron_schedule="*/5 * * * *"
    )
    
    # 2. Host Discovery Rule
    print("Creating Host Discovery Rule...")
    await client.create_saved_search(
        name="Forensiq_Alert_Host_Discovery",
        search_query='search index=* (ping OR arp OR "Test-NetConnection") | stats count by src_ip | where count > 10',
        cron_schedule="*/5 * * * *"
    )
    
    # 3. Admin Login Rule
    print("Creating Admin Login Rule...")
    await client.create_saved_search(
        name="Forensiq_Alert_Admin_Login",
        search_query='search index=* EventCode=4624 (user="*admin*" OR user="root" OR Group="Administrators")',
        cron_schedule="*/5 * * * *"
    )
    
    # 4. Dashboard
    print("Creating Splunk Dashboard...")
    xml_dashboard = """
    <dashboard>
      <label>Forensiq Monitoring</label>
      <row>
        <panel>
          <title>Port Scanning Activity</title>
          <chart>
            <search>
              <query>index=* (dest_port=* OR action=blocked) | timechart count by src_ip</query>
              <earliest>-24h@h</earliest>
              <latest>now</latest>
            </search>
            <option name="charting.chart">line</option>
          </chart>
        </panel>
        <panel>
          <title>Admin Logins</title>
          <table>
            <search>
              <query>index=* EventCode=4624 (user="*admin*" OR user="root" OR Group="Administrators") | table _time, user, dest, src_ip</query>
              <earliest>-24h@h</earliest>
              <latest>now</latest>
            </search>
          </table>
        </panel>
      </row>
    </dashboard>
    """
    await client.create_dashboard("forensiq_monitoring", "Forensiq Monitoring", xml_dashboard)
    
    print("Setup complete!")
    await client.close()

if __name__ == "__main__":
    import sys
    import os
    # Add backend dir to path so we can run from anywhere
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    asyncio.run(setup())
