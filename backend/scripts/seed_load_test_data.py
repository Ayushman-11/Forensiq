"""
Seed 100,000 Realistic Alerts, Incidents, and 50 SOC Analyst Accounts.

Simulates enterprise-scale volume:
  - 100,000 alerts with realistic severity, tenant, MITRE, and temporal distributions
  - 1,000 incidents linked to alert groups with precomputed counters
  - 50 SOC analyst accounts with JWT access tokens pre-signed for immediate load testing
"""

import asyncio
import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from motor.motor_asyncio import AsyncIOMotorClient

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.security import create_access_token, hash_password


TENANTS = ["default", "tenant-finance", "tenant-healthcare"]
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHTS = [0.10, 0.25, 0.45, 0.20]

STATUSES = ["open", "investigating", "Closed", "Suppressed", "Escalated"]
STATUS_WEIGHTS = [0.55, 0.15, 0.20, 0.05, 0.05]

TECHNIQUES = [
    ("T1110", "Credential Access", "brute_force_login", "Brute Force Attack"),
    ("T1059.001", "Execution", "suspicious_powershell_execution", "Suspicious PowerShell Execution"),
    ("T1547.001", "Persistence", "registry_run_key_persistence", "Registry Persistence via Run Key"),
    ("T1071", "Command and Control", "suspicious_external_connection", "Suspicious External C2 Connection"),
    ("T1071.004", "Command and Control", "dns_suspicious_query", "DNS Tunneling / Suspicious Lookup"),
]

HOSTS = [f"WKS-{i:03d}" for i in range(1, 100)] + ["DC-01", "DC-02", "SRV-APP-01", "SRV-DB-01", "SRV-WEB-01"]
USERS = [f"user_{i:03d}" for i in range(1, 200)] + ["SYSTEM", "Administrator", "svc_backup", "svc_sql"]


def generate_analysts(count: int = 50) -> tuple[list[dict], list[dict]]:
    """Generate 50 SOC analyst accounts and pre-signed JWT tokens."""
    analyst_docs = []
    auth_records = []
    hashed_pwd = hash_password("SOCAnalyst2026!Secure")

    for i in range(1, count + 1):
        uid = f"analyst-user-{i:03d}"
        email = f"analyst_{i:02d}@forensiq.ai"
        role = "soc_manager" if i <= 5 else ("tier2_analyst" if i <= 20 else "tier1_analyst")
        tenant = TENANTS[i % len(TENANTS)]

        user_doc = {
            "_id": uid,
            "email": email,
            "hashed_password": hashed_pwd,
            "role": role,
            "org_id": tenant,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }
        analyst_docs.append(user_doc)

        token = create_access_token(user_id=uid, email=email, role=role)
        auth_records.append({
            "id": uid,
            "email": email,
            "role": role,
            "org_id": tenant,
            "token": token,
        })

    return analyst_docs, auth_records


def generate_alerts_batch(count: int, start_idx: int) -> list[dict]:
    """Generate a realistic batch of alert records."""
    batch = []
    now = datetime.now(timezone.utc)

    for i in range(count):
        idx = start_idx + i
        tech, tactic, rule_name, title_base = random.choice(TECHNIQUES)
        sev = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
        status = random.choices(STATUSES, weights=STATUS_WEIGHTS)[0]
        tenant = random.choice(TENANTS)
        host = random.choice(HOSTS)
        user = random.choice(USERS)

        # Distributed over the last 30 days
        age_seconds = random.randint(60, 30 * 86400)
        detected_at = now - timedelta(seconds=age_seconds)

        risk_score = (
            random.randint(85, 100) if sev == "critical" else (
                random.randint(60, 84) if sev == "high" else (
                    random.randint(30, 59) if sev == "medium" else random.randint(10, 29)
                )
            )
        )

        alert_id = f"alert-{idx:07d}"
        doc = {
            "_id": alert_id,
            "org_id": tenant,
            "title": f"[{sev.upper()}] {title_base} on {host}",
            "severity": sev,
            "status": status,
            "risk_score": risk_score,
            "rule_name": rule_name,
            "mitre_technique": tech,
            "mitre_tactic": tactic,
            "host": host,
            "user": user,
            "count": random.randint(1, 15),
            "detected_at": detected_at.isoformat(),
            "created_at": detected_at.isoformat(),
            "last_seen": detected_at.isoformat(),
            "sla": {
                "ack_deadline": (detected_at + timedelta(minutes=15)).isoformat(),
                "resolve_deadline": (detected_at + timedelta(hours=4)).isoformat(),
                "ack_breached": False,
                "resolve_breached": False,
            },
        }

        # Context-specific fields
        if rule_name == "suspicious_powershell_execution":
            doc["command_line"] = "powershell.exe -noni -bypass -enc SQBFAFgA..."
        elif rule_name == "dns_suspicious_query":
            doc["dns_query"] = f"c2-{random.randint(10, 99)}.ngrok-free.app"
        elif rule_name == "suspicious_external_connection":
            doc["dest_ip"] = f"198.51.100.{random.randint(1, 254)}"
            doc["dest_port"] = random.choice([4444, 8080, 1337, 9001])
        elif rule_name == "registry_run_key_persistence":
            doc["registry_key"] = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

        batch.append(doc)
    return batch


async def seed_data(total_alerts: int = 100000, total_incidents: int = 1000):
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.MONGO_DB_NAME]

    print("=" * 70)
    print(f"  FORENSIQ DATA SEEDER: {total_alerts:,} ALERTS & 50 ANALYSTS")
    print(f"  Target DB: {settings.MONGO_DB_NAME} at {settings.MONGO_URI}")
    print("=" * 70)

    # 1. Seed Analysts and save JWT tokens
    print("\n1. Seeding 50 SOC Analyst Accounts & Generating JWT Tokens...")
    analyst_docs, auth_records = generate_analysts(50)
    for doc in analyst_docs:
        await db["users"].replace_one({"_id": doc["_id"]}, doc, upsert=True)

    tokens_file = backend_dir / "tests" / "load" / "analysts_tokens.json"
    tokens_file.parent.mkdir(parents=True, exist_ok=True)
    with open(tokens_file, "w", encoding="utf-8") as f:
        json.dump(auth_records, f, indent=2)
    print(f"   ✓ Seeded 50 analysts into MongoDB 'users'")
    print(f"   ✓ Saved JWT tokens to {tokens_file}")

    # 2. Seed Alerts in Chunks of 5,000
    print(f"\n2. Seeding {total_alerts:,} Alerts in Batches of 5,000...")
    batch_size = 5000
    total_seeded = 0
    t0 = asyncio.get_event_loop().time()

    for start in range(0, total_alerts, batch_size):
        chunk = generate_alerts_batch(batch_size, start)
        try:
            await db["alerts"].insert_many(chunk, ordered=False)
        except Exception:
            # If re-running, update docs
            for doc in chunk:
                await db["alerts"].replace_one({"_id": doc["_id"]}, doc, upsert=True)
        total_seeded += len(chunk)
        elapsed = asyncio.get_event_loop().time() - t0
        rate = total_seeded / max(elapsed, 0.001)
        print(f"   -> Seeded {total_seeded:,} / {total_alerts:,} alerts ({rate:,.0f} alerts/sec)")

    # 3. Seed Incidents
    print(f"\n3. Seeding {total_incidents:,} Incidents with Precomputed Counters...")
    incident_docs = []
    now = datetime.now(timezone.utc)
    for i in range(1, total_incidents + 1):
        tenant = random.choice(TENANTS)
        sev = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
        # Link 5-20 alerts to each incident
        alert_start = (i * 15) % total_alerts
        member_ids = [f"alert-{alert_start + j:07d}" for j in range(random.randint(5, 20))]
        open_cnt = random.randint(1, len(member_ids))
        closed_cnt = len(member_ids) - open_cnt

        incident_docs.append({
            "_id": f"inc-{i:05d}",
            "incident_number": i,
            "org_id": tenant,
            "title": f"Incident #{i:04d}: Coordinated Threat Pattern on {tenant}",
            "severity": sev,
            "status": "Closed" if open_cnt == 0 else "Active",
            "state": "closed" if open_cnt == 0 else "open",
            "alert_ids": member_ids,
            "open_alerts_count": open_cnt,
            "closed_alerts_count": closed_cnt,
            "created_at": (now - timedelta(days=random.randint(1, 28))).isoformat(),
            "updated_at": now.isoformat(),
        })

    for i in range(0, len(incident_docs), 500):
        chunk = incident_docs[i:i + 500]
        try:
            await db["incidents"].insert_many(chunk, ordered=False)
        except Exception:
            for doc in chunk:
                await db["incidents"].replace_one({"_id": doc["_id"]}, doc, upsert=True)

    print(f"   ✓ Seeded {total_incidents:,} incidents")

    # 4. Verify MongoDB Indexes
    print("\n4. Ensuring High-Performance Indexes...")
    await db["alerts"].create_index([("org_id", 1), ("detected_at", -1)])
    await db["alerts"].create_index([("org_id", 1), ("status", 1)])
    await db["alerts"].create_index([("org_id", 1), ("severity", 1)])
    await db["alerts"].create_index([("org_id", 1), ("mitre_technique", 1)])
    await db["incidents"].create_index([("org_id", 1), ("created_at", -1)])
    await db["incidents"].create_index([("org_id", 1), ("state", 1)])
    print("   ✓ Indexes verified: (org_id, detected_at), (org_id, status), (org_id, mitre_technique), etc.")

    print("\n" + "=" * 70)
    print("  SEEDING COMPLETE: READY FOR LOCUST & K6 LOAD TESTS")
    print("=" * 70)
    client.close()


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    asyncio.run(seed_data(count))
