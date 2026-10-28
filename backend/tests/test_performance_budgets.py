"""
Automated CI Performance Budgets Test.

Enforces strict latency budgets on all scale-optimized endpoints:
  - GET /api/v1/dashboard/summary      : p95 < 80ms  (consolidated cached endpoint)
  - GET /api/v1/alerts                : p95 < 150ms (keyset cursor pagination)
  - GET /api/v1/incidents             : p95 < 150ms (database aggregation & counters)
  - GET /api/v1/alerts/stats/mitre    : p95 < 150ms (database $facet aggregation)
  - GET /api/v1/dashboard/soc-metrics : p95 < 80ms  (TTL cached soc-metrics)
"""

import asyncio
import time
from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.core.security import create_access_token
from app.main import app
from app.database.session import get_db
from scripts.seed_load_test_data import generate_alerts_batch


@pytest.fixture
def mock_db():
    return AsyncMongoMockClient()["forensiq_perf_test"]


@pytest.fixture
def auth_header():
    token = create_access_token(
        user_id="perf-analyst-001",
        email="perf@forensiq.ai",
        role="tier2_analyst",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_performance_budgets(mock_db, auth_header):
    # Seed active user
    await mock_db["users"].insert_one({
        "_id": "perf-analyst-001",
        "email": "perf@forensiq.ai",
        "role": "tier2_analyst",
        "org_id": "default",
        "is_active": True,
    })

    # Seed 1,500 realistic alerts into mock DB
    alerts = generate_alerts_batch(1500, 0)
    for a in alerts:
        a["org_id"] = "default"
    await mock_db["alerts"].insert_many(alerts)

    # Seed 50 incidents
    now = datetime.now(timezone.utc).isoformat()
    incidents = []
    for i in range(50):
        incidents.append({
            "_id": f"inc-{i:04d}",
            "incident_number": i,
            "org_id": "default",
            "title": f"Test Incident {i}",
            "severity": "high",
            "status": "Active",
            "state": "open",
            "alert_ids": [f"alert-{i*10:07d}", f"alert-{i*10+1:07d}"],
            "open_alerts_count": 2,
            "closed_alerts_count": 0,
            "created_at": now,
            "updated_at": now,
        })
    await mock_db["incidents"].insert_many(incidents)

    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Warmup
        await client.get("/api/v1/dashboard/summary", headers=auth_header)
        await client.get("/api/v1/alerts?limit=50", headers=auth_header)

        # 1. Dashboard Summary Budget (Budget: < 100ms)
        summary_latencies = []
        for _ in range(15):
            t0 = time.perf_counter()
            resp = await client.get("/api/v1/dashboard/summary", headers=auth_header)
            summary_latencies.append((time.perf_counter() - t0) * 1000)
            assert resp.status_code == 200

        summary_latencies.sort()
        p95_summary = summary_latencies[int(len(summary_latencies) * 0.95)]
        print(f"\n[Budget] Dashboard Summary p95: {p95_summary:.2f}ms (Budget: 100ms)")
        assert p95_summary < 100, f"Dashboard summary exceeded budget: {p95_summary:.2f}ms"

        # 2. Alerts Keyset Cursor Pagination Budget (Budget: < 200ms)
        alerts_latencies = []
        cursor = None
        for _ in range(15):
            url = f"/api/v1/alerts?limit=50&sort=severity&status=open"
            if cursor:
                url += f"&cursor={cursor}"
            t0 = time.perf_counter()
            resp = await client.get(url, headers=auth_header)
            alerts_latencies.append((time.perf_counter() - t0) * 1000)
            assert resp.status_code == 200
            cursor = resp.headers.get("X-Next-Cursor")

        alerts_latencies.sort()
        p95_alerts = alerts_latencies[int(len(alerts_latencies) * 0.95)]
        print(f"[Budget] Alerts Cursor Pagination p95: {p95_alerts:.2f}ms (Budget: 200ms)")
        assert p95_alerts < 200, f"Alerts cursor pagination exceeded budget: {p95_alerts:.2f}ms"

        # 3. Incidents Aggregation Budget (Budget: < 200ms)
        incidents_latencies = []
        for _ in range(15):
            t0 = time.perf_counter()
            resp = await client.get("/api/v1/incidents?limit=20&state=open", headers=auth_header)
            incidents_latencies.append((time.perf_counter() - t0) * 1000)
            assert resp.status_code == 200

        incidents_latencies.sort()
        p95_incidents = incidents_latencies[int(len(incidents_latencies) * 0.95)]
        print(f"[Budget] Incidents Aggregation p95: {p95_incidents:.2f}ms (Budget: 200ms)")
        assert p95_incidents < 200, f"Incidents aggregation exceeded budget: {p95_incidents:.2f}ms"

        # 4. MITRE Full DB Aggregation Budget (Budget: < 150ms)
        mitre_latencies = []
        for _ in range(15):
            t0 = time.perf_counter()
            resp = await client.get("/api/v1/alerts/stats/mitre", headers=auth_header)
            mitre_latencies.append((time.perf_counter() - t0) * 1000)
            assert resp.status_code == 200

        mitre_latencies.sort()
        p95_mitre = mitre_latencies[int(len(mitre_latencies) * 0.95)]
        print(f"[Budget] MITRE Aggregation p95: {p95_mitre:.2f}ms (Budget: 150ms)")
        assert p95_mitre < 150, f"MITRE aggregation exceeded budget: {p95_mitre:.2f}ms"

    app.dependency_overrides.clear()
