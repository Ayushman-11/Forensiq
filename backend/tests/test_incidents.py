"""
Incident grouping: link keys, windows, merging, rebuild parity, derived state and the API.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.api.v1.endpoints import incidents as incidents_module
from app.database.session import get_db
from app.normalization.noise import NoiseFilter
from app.services.incidents import link_alert, link_alerts, link_keys, rebuild_incidents

T0 = datetime(2026, 10, 1, 12, 0)
HASH = "a" * 64
NOISE = NoiseFilter([], [], ["githubusercontent.com", "pastebin.com"])
ANALYST = {"id": "u1", "email": "l1@corp.local", "role": "soc_analyst", "org_id": "acme"}
MANAGER = {"id": "u2", "email": "mgr@corp.local", "role": "soc_manager", "org_id": "acme"}


def alert(i, host="h1", user="CORP\\alice", minutes=0, iocs=None, severity="high", org="acme", rule="r1", status="New", **kw):
    return {"_id": f"a{i}", "org_id": org, "title": f"alert {i}", "host": host, "user": user, "severity": severity,
            "rule_name": rule, "status": status, "first_seen": T0 + timedelta(minutes=minutes),
            "created_at": T0 + timedelta(minutes=minutes), "extracted_iocs": iocs or [], **kw}


@pytest.fixture
def db():
    return AsyncMongoMockClient()["incidents"]


async def group(db, *alerts):
    await db["alerts"].insert_many([dict(a) for a in alerts])
    await link_alerts(db, alerts, NOISE)
    return {a["_id"]: (await db["alerts"].find_one({"_id": a["_id"]})).get("incident_id") for a in alerts}


def test_link_keys_skip_generic_identities_and_shared_infrastructure():
    keys = link_keys(alert(1, host="H1", user="SYSTEM", iocs=[HASH, "raw.githubusercontent.com", "evil.example", "185.199.108.133", "::1"]), NOISE)
    assert keys == ["host:h1", f"hash:{HASH}", "domain:evil.example"]
    for generic in ("NT AUTHORITY\\SYSTEM", "ATTACKRANGE\\Administrator", "WIN01$", "root", "Unknown", "-"):
        assert not any(k.startswith("user:") for k in link_keys(alert(1, user=generic), NOISE)), generic
    assert "user:corp\\alice" in link_keys(alert(1, user="CORP\\Alice"), NOISE)


@pytest.mark.asyncio
async def test_same_host_within_window_groups_and_gap_splits(db):
    ids = await group(db, alert(1, minutes=0, user="u1"), alert(2, minutes=60, user="u2"), alert(3, minutes=60 * 24, user="u3"))
    assert ids["a1"] == ids["a2"] != ids["a3"]
    incident = await db["incidents"].find_one({"_id": ids["a1"]})
    assert incident["alert_count"] == 2 and incident["last_seen"] == T0 + timedelta(minutes=60)


@pytest.mark.asyncio
async def test_default_admin_account_does_not_fuse_different_hosts(db):
    ids = await group(db, alert(1, host="h1", user="LAB\\Administrator"), alert(2, host="h2", user="LAB\\Administrator", minutes=5))
    assert ids["a1"] != ids["a2"]


@pytest.mark.asyncio
async def test_shared_hash_links_hosts_but_shared_hosting_domain_does_not(db):
    ids = await group(
        db,
        alert(1, host="h1", user="u1", iocs=["raw.githubusercontent.com"]),
        alert(2, host="h2", user="u2", minutes=5, iocs=["raw.githubusercontent.com"]),
        alert(3, host="h3", user="u3", minutes=6, iocs=[HASH]),
        alert(4, host="h4", user="u4", minutes=7, iocs=[HASH]),
    )
    assert ids["a1"] != ids["a2"]
    assert ids["a3"] == ids["a4"]
    incident = await db["incidents"].find_one({"_id": ids["a3"]})
    assert sorted(incident["hosts"]) == ["h3", "h4"]


@pytest.mark.asyncio
async def test_an_alert_that_bridges_two_incidents_merges_them(db):
    ids = await group(
        db,
        alert(1, host="h1", user="u1", severity="low"),
        alert(2, host="h2", user="u2", minutes=10, severity="critical"),
        alert(3, host="h1", user="u2", minutes=20),  # same host as a1, same user as a2
    )
    assert len(set(ids.values())) == 1
    assert await db["incidents"].count_documents({}) == 1
    incident = await db["incidents"].find_one({})
    assert incident["alert_count"] == 3 and incident["severity"] == "critical"
    assert sorted(incident["hosts"]) == ["h1", "h2"]


@pytest.mark.asyncio
async def test_tenants_never_share_incidents(db):
    ids = await group(db, alert(1, org="acme"), alert(2, org="other", minutes=1))
    assert ids["a1"] != ids["a2"]


@pytest.mark.asyncio
async def test_alerts_without_keys_stay_ungrouped(db):
    assert (await link_alert(db, alert(1, host="Unknown", user="SYSTEM"), NOISE)) is None


@pytest.mark.asyncio
async def test_rebuild_reproduces_incremental_grouping(db):
    alerts = [alert(1, user="u1"), alert(2, host="h2", user="u2", minutes=5, iocs=[HASH]), alert(3, host="h3", user="u3", minutes=9, iocs=[HASH]),
              alert(4, user="u4", minutes=600)]
    incremental = await group(db, *alerts)
    shape = lambda ids: sorted(sorted(k for k, v in ids.items() if v == i) for i in set(ids.values()))

    result = await rebuild_incidents(db, "acme", NOISE)
    rebuilt = {a["_id"]: a.get("incident_id") async for a in db["alerts"].find({})}
    assert shape(rebuilt) == shape(incremental)
    assert result == {"alerts": 4, "linked": 4, "incidents": 3}


async def api(db, user, method, path, router, prefix):
    app = FastAPI()
    app.include_router(router, prefix=prefix)

    async def _db():
        return db

    async def _user():
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path)


@pytest.mark.asyncio
async def test_incident_state_is_derived_from_member_alerts(db):
    await group(
        db,
        alert(1, status="Closed", verdict="true_positive"),
        alert(2, minutes=5, status="Investigated", assignee_email="l1@corp.local"),
        alert(3, host="h9", user="z", minutes=1, severity="low"),
    )
    rows = (await api(db, ANALYST, "GET", "/incidents", incidents_module.router, "/incidents")).json()
    assert [r["state"] for r in rows] == ["open", "open"]  # both have an open member
    big = next(r for r in rows if r["alert_count"] == 2)
    assert big["open_count"] == 1 and big["owner"] == "l1@corp.local" and big["status_counts"] == {"Closed": 1, "Investigated": 1}

    await db["alerts"].update_one({"_id": "a2"}, {"$set": {"status": "Closed"}})
    resolved = (await api(db, ANALYST, "GET", "/incidents?state=resolved", incidents_module.router, "/incidents")).json()
    assert [r["alert_count"] for r in resolved] == [2]


@pytest.mark.asyncio
async def test_open_incidents_are_ordered_by_severity(db):
    await group(db, alert(1, host="low-host", user="a", severity="low"), alert(2, host="crit-host", user="b", severity="critical", minutes=1))
    rows = (await api(db, ANALYST, "GET", "/incidents", incidents_module.router, "/incidents")).json()
    assert [r["severity"] for r in rows] == ["critical", "low"]


@pytest.mark.asyncio
async def test_incident_detail_lists_members_and_link_keys_and_is_tenant_scoped(db):
    ids = await group(db, alert(1), alert(2, minutes=3, iocs=[HASH]), alert(3, org="other", host="h1", minutes=1))
    detail = (await api(db, ANALYST, "GET", f"/incidents/{ids['a1']}", incidents_module.router, "/incidents")).json()
    assert [m["_id"] for m in detail["alerts"]] == ["a1", "a2"]
    assert "host:h1" in detail["link_keys"]
    assert detail["first_seen"].endswith("+00:00")
    foreign = await api(db, ANALYST, "GET", f"/incidents/{ids['a3']}", incidents_module.router, "/incidents")
    assert foreign.status_code == 404


@pytest.mark.asyncio
async def test_only_managers_can_rebuild_and_it_is_audited(db):
    await db["alerts"].insert_many([alert(1), alert(2, minutes=2)])
    assert (await api(db, ANALYST, "POST", "/incidents/rebuild", incidents_module.router, "/incidents")).status_code == 403
    r = await api(db, MANAGER, "POST", "/incidents/rebuild", incidents_module.router, "/incidents")
    assert r.status_code == 200 and r.json()["incidents"] == 1
    assert (await db["audit_logs"].find_one({"action": "incidents.rebuilt"}))["metadata"]["alerts"] == 2



@pytest.mark.asyncio
async def test_alert_queue_can_filter_by_incident(db):
    ids = await group(db, alert(1), alert(2, host="h9", user="x", minutes=1))
    r = await api(db, ANALYST, "GET", f"/alerts/?incident={ids['a1']}&status=all", alerts_module.router, "/alerts")
    assert [a["_id"] for a in r.json()] == ["a1"]


@pytest.mark.asyncio
async def test_incidents_pagination_and_headers(db):
    # Create 5 distinct incidents
    alerts_to_group = [alert(i, host=f"host-{i}", user=f"user-{i}", minutes=i) for i in range(1, 6)]
    await group(db, *alerts_to_group)

    # Fetch page 1 (2 items)
    r1 = await api(db, ANALYST, "GET", "/incidents?limit=2&skip=0", incidents_module.router, "/incidents")
    assert r1.status_code == 200
    p1 = r1.json()
    assert len(p1) == 2
    assert r1.headers.get("x-next-cursor") is not None

    # Fetch page 2 (2 items)
    r2 = await api(db, ANALYST, "GET", "/incidents?limit=2&skip=2", incidents_module.router, "/incidents")
    assert r2.status_code == 200
    p2 = r2.json()
    assert len(p2) == 2
    # Ensure distinct from page 1
    assert {i["id"] for i in p1}.isdisjoint({i["id"] for i in p2})
