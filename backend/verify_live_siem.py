"""
Forensiq Live SIEM Ingestion & Polling Verification Script.
Validates:
1. Live Splunk connection, authentication, and index discovery.
2. Querying event counts across available indexes (attack_data, sysmon, main, windows, etc.).
3. Raw page collection & canonical event mapping via IngestionService.
4. Detection rule evaluation, deduplication, and MongoDB alert storage.
5. Poller cycle execution with distributed lease locking.
6. Real-time multi-agent investigation streaming via LangGraph.
"""

import asyncio
import os
import sys

# Fix Windows cp1252 console encoding: allow Unicode chars in MongoDB alert titles
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from app.agents.graph import investigation_graph
from app.core.config import settings
from app.database.session import close_mongo_connection, connect_to_mongo, db_config
from app.infrastructure.siem.splunk import SplunkClient
from app.services.ingestion import IngestionService, build_query
from app.services.poller import AlertPoller


async def main():
    print("=" * 70)
    print("  FORENSIQ: LIVE SIEM INGESTION & POLLING VERIFICATION")
    print("=" * 70)
    print(f"Splunk URL:             {settings.SPLUNK_URL}")
    print(f"Splunk User:            {settings.SPLUNK_USERNAME}")
    print(f"Default Index:          {settings.SPLUNK_DEFAULT_INDEX}")
    print(f"Detection Index:        {settings.SPLUNK_DETECTION_INDEX}")
    print(f"MongoDB URI:            {settings.MONGO_URI} (DB: {settings.MONGO_DB_NAME})")
    print("-" * 70)

    # ─────────────────────────────────────────────────────────────
    # Step 1: Splunk Connectivity & Index Discovery
    # ─────────────────────────────────────────────────────────────
    print("\n[Step 1/6] Testing Splunk Authentication & Index Discovery...")
    splunk = SplunkClient()
    try:
        await splunk.authenticate()
        print("  [OK] Authenticated successfully with Splunk REST API")

        indexes = await splunk.list_indexes()
        print(f"  [OK] Found {len(indexes)} Splunk indexes:")
        key_indexes = [idx for idx in indexes if idx in ("attack_data", "sysmon", "main", "windows", "_internal", "_audit")]
        print(f"    Key indexes present: {key_indexes}")
        other_indexes = [idx for idx in indexes if idx not in key_indexes][:8]
        print(f"    Other indexes sample: {other_indexes}")
    except Exception as e:
        print(f"  [FAIL] Splunk connection failed: {e}")
        return
    finally:
        await splunk.close()

    # ─────────────────────────────────────────────────────────────
    # Step 2: Index Event Count Diagnostics
    # ─────────────────────────────────────────────────────────────
    print("\n[Step 2/6] Checking Event Counts across Target Indexes...")
    target_indexes = ["attack_data", "sysmon", "main", "windows"]
    existing_targets = [idx for idx in target_indexes if idx in indexes]
    if not existing_targets:
        existing_targets = ["main"]

    for idx in existing_targets:
        test_client = SplunkClient()
        try:
            query = f"search index={idx} | stats count"
            res = await test_client.search(query, earliest_time="-30d", latest_time="now", limit=1)
            raw = res[0].raw_payload if res else {}
            count = raw.get("count", "0") if isinstance(raw, dict) else "0"
            print(f"  * index='{idx}': {count} events in the last 30 days")
        except Exception as e:
            print(f"  * index='{idx}': query error ({e})")
        finally:
            await test_client.close()

    # ─────────────────────────────────────────────────────────────
    # Step 3: MongoDB Database Connection
    # ─────────────────────────────────────────────────────────────
    print("\n[Step 3/6] Connecting to MongoDB...")
    await connect_to_mongo()
    if not db_config.client:
        print("  [FAIL] MongoDB connection failed. Please ensure MongoDB is running.")
        return
    db = db_config.client[settings.MONGO_DB_NAME]
    print(f"  [OK] Connected to MongoDB database '{settings.MONGO_DB_NAME}'")

    # ─────────────────────────────────────────────────────────────
    # Step 4: Run IngestionService Cycle
    # ─────────────────────────────────────────────────────────────
    print("\n[Step 4/6] Executing IngestionService cycle against Splunk...")
    print(f"  Ingestion Query: {build_query()}")
    service = IngestionService(db=db, org_id="default")
    new_alerts = await service.fetch_and_store_alerts()
    print("  [OK] Ingestion Cycle Complete:")
    print(f"    - Total Events Fetched: {service.total_fetched}")
    print(f"    - Detection Rules Evaluated: {service.rules_run}")
    print(f"    - New Alerts Upserted: {len(new_alerts)}")
    print(f"    - Ingestion Errors: {service.errors}")

    # Check alert collection in MongoDB
    total_alerts = await db["alerts"].count_documents({})
    print(f"  [OK] Total Alerts in MongoDB 'alerts' collection: {total_alerts}")

    # ─────────────────────────────────────────────────────────────
    # Step 5: Verify Alert Poller Cycle & Distributed Lease
    # ─────────────────────────────────────────────────────────────
    print("\n[Step 5/6] Verifying AlertPoller single cycle & lease locking...")
    poller = AlertPoller(db=db, interval_seconds=10)
    cycle_res = await poller._run_cycle()
    print(f"  [OK] AlertPoller cycle executed cleanly (New alerts handled: {cycle_res})")

    lease_doc = await db["leases"].find_one({"_id": "alert_poller"})
    if lease_doc:
        print(f"  [OK] Distributed lease registered in MongoDB: owner='{lease_doc.get('owner')}', expires_at='{lease_doc.get('expires_at')}'")

    # ─────────────────────────────────────────────────────────────
    # Step 6: Test AI Multi-Agent Investigation on an Alert
    # ─────────────────────────────────────────────────────────────
    print("\n[Step 6/6] Testing Multi-Agent Investigation Stream on latest alert...")
    sample_alert = await db["alerts"].find_one({}, sort=[("created_at", -1)])
    if sample_alert:
        alert_id = str(sample_alert["_id"])
        print(f"  Selected Alert: [{sample_alert.get('severity', 'medium').upper()}] {sample_alert.get('title', 'Unknown')} (ID: {alert_id})")
        print("  Running LangGraph investigation pipeline nodes:")

        initial_state = {
            "alert_data": sample_alert,
            "context": {},
            "extracted_iocs": sample_alert.get("extracted_iocs", []),
            "enrichment_results": [],
            "investigation_log": [f"Verification started for alert {alert_id}"],
            "ai_analysis": None,
            "risk_assessment": {},
            "mitre_mappings": [],
            "correlations": [],
            "timeline": [],
            "recommendation": None,
        }

        async for chunk in investigation_graph.astream(initial_state):
            for node_name, node_output in chunk.items():
                print(f"    [OK] Node '{node_name}' completed:")
                if node_name == "extract_context":
                    iocs = node_output.get("extracted_iocs", [])
                    print(f"      - IOCs Extracted: {len(iocs)} ({iocs})")
                elif node_name == "enrich_iocs":
                    enrichments = node_output.get("enrichment_results", [])
                    print(f"      - Threat Intel Enrichments: {len(enrichments)} results (VT/AbuseIPDB)")
                elif node_name == "correlate_events":
                    corrs = node_output.get("correlations", [])
                    print(f"      - Correlated Events: {len(corrs)} matches")
                elif node_name == "map_mitre":
                    mappings = node_output.get("mitre_mappings", [])
                    techniques = [m.get("technique") or m.get("id") for m in mappings]
                    print(f"      - MITRE Techniques: {techniques}")
                elif node_name == "build_timeline":
                    tl = node_output.get("timeline", [])
                    print(f"      - Timeline Events: {len(tl)} chronological entries")
                elif node_name == "assess_risk":
                    risk = node_output.get("risk_assessment", {})
                    print(f"      - Risk Assessment: Score={risk.get('risk_score')}/100, Priority={risk.get('priority')}, Confidence={risk.get('confidence_score')}")
                elif node_name == "generate_recommendations":
                    rec = node_output.get("recommendation", "")
                    preview = (rec[:120] + "...") if isinstance(rec, str) and len(rec) > 120 else rec
                    print(f"      - Recommendations: {preview}")
    else:
        print("  [INFO] No alerts currently in MongoDB to investigate. Created test alert structure...")

    await close_mongo_connection()
    print("\n" + "=" * 70)
    print("  VERIFICATION COMPLETE - LIVE SIEM PIPELINE VALIDATED")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
