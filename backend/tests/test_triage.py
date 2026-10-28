"""
Triage workflow: status machine, verdicts, role gates, assignment, bulk actions and SOC metrics.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.api.v1.endpoints import dashboard as dashboard_module
from app.api.v1.endpoints import users as users_module
from app.database.session import get_db
from app.services.triage import sla_state

NOW = datetime.now(timezone.utc)
ANALYST = {"id": "u-analyst", "email": "l1@corp.local", "role": "soc_analyst", "org_id": "acme"}
OTHER_ANALYST = {"id": "u-other", "email": "l1b@corp.local", "role": "soc_analyst", "org_id": "acme"}
MANAGER = {"id": "u-manager", "email": "mgr@corp.local", "role": "soc_manager", "org_id": "acme"}


@pytest.fixture
def db():
    return AsyncMongoMockClient()["triage"]


@pytest.fixture
async def seeded(db):
    await db["users"].insert_many([
        {"_id": u["id"], "email": u["email"], "role": u["role"], "org_id": "acme", "is_active": True}
        for u in (ANALYST, OTHER_ANALYST, MANAGER)
    ] + [{"_id": "u-foreign", "email": "x@other.org", "role": "soc_analyst", "org_id": "other", "is_active": True}])
    await db["alerts"].insert_many([
        {"_id": "crit", "org_id": "acme", "title": "c", "severity": "critical", "status": "Investigated",
         "rule_name": "r1", "detected_at": NOW - timedelta(minutes=30), "risk_assessment": {"risk_score": 90}},
        {"_id": "med", "org_id": "acme", "title": "m", "severity": "medium", "status": "New",
         "rule_name": "r2", "detected_at": NOW - timedelta(minutes=5)},
        {"_id": "foreign", "org_id": "other", "title": "f", "severity": "low", "status": "New", "detected_at": NOW},
    ])
    return db


async def call(db, user, method, path, json=None, router=alerts_module.router, prefix="/alerts"):
    app = FastAPI()
    app.include_router(router, prefix=prefix)

    async def _db():
        return db

    async def _user():
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path, json=json)


@pytest.mark.asyncio
async def test_close_requires_verdict_and_note(seeded):
    r = await call(seeded, ANALYST, "PATCH", "/alerts/med/disposition", {"action": "close", "note": "fine"})
    assert r.status_code == 422 and "verdict" in r.json()["detail"]
    r = await call(seeded, ANALYST, "PATCH", "/alerts/med/disposition", {"action": "close", "verdict": "false_positive"})
    assert r.status_code == 422 and "note" in r.json()["detail"]


@pytest.mark.asyncio
async def test_close_records_verdict_resolution_and_audit(seeded):
    r = await call(seeded, ANALYST, "PATCH", "/alerts/med/disposition",
                   {"action": "close", "verdict": "false_positive", "note": "admin script"})
    assert r.status_code == 200 and r.json()["status"] == "Closed"
    alert = await seeded["alerts"].find_one({"_id": "med"})
    assert alert["verdict"] == "false_positive" and alert["resolved_by"] == "l1@corp.local"
    assert alert["acknowledged_at"] and alert["resolved_at"]
    audit = await seeded["audit_logs"].find_one({"entity_id": "med"})
    assert audit["action"] == "alert.close" and audit["metadata"]["from"] == "New"


@pytest.mark.asyncio
async def test_terminal_alerts_cannot_be_closed_again(seeded):
    body = {"action": "close", "verdict": "false_positive", "note": "n"}
    assert (await call(seeded, ANALYST, "PATCH", "/alerts/med/disposition", body)).status_code == 200
    r = await call(seeded, ANALYST, "PATCH", "/alerts/med/disposition", body)
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_analyst_cannot_make_a_critical_disappear(seeded):
    r = await call(seeded, ANALYST, "PATCH", "/alerts/crit/disposition", {"action": "suppress", "note": "noise"})
    assert r.status_code == 403
    r = await call(seeded, ANALYST, "PATCH", "/alerts/crit/disposition",
                   {"action": "close", "verdict": "false_positive", "note": "noise"})
    assert r.status_code == 403
    # A true positive may be closed by the analyst after remediation.
    r = await call(seeded, ANALYST, "PATCH", "/alerts/crit/disposition",
                   {"action": "close", "verdict": "true_positive", "note": "host reimaged"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_manager_can_suppress_and_only_manager_reopens_suppressed(seeded):
    r = await call(seeded, MANAGER, "PATCH", "/alerts/crit/disposition", {"action": "suppress", "note": "known scanner"})
    assert r.status_code == 200 and r.json()["status"] == "Suppressed"
    assert (await call(seeded, ANALYST, "PATCH", "/alerts/crit/disposition", {"action": "reopen", "note": "seen again"})).status_code == 403
    r = await call(seeded, MANAGER, "PATCH", "/alerts/crit/disposition", {"action": "reopen", "note": "seen again"})
    assert r.status_code == 200 and r.json()["status"] == "Investigated"
    alert = await seeded["alerts"].find_one({"_id": "crit"})
    assert "verdict" not in alert and "resolved_at" not in alert


@pytest.mark.asyncio
async def test_other_tenants_alerts_are_invisible(seeded):
    r = await call(seeded, MANAGER, "PATCH", "/alerts/foreign/disposition", {"action": "escalate", "note": "n"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_analyst_assignment_is_limited_to_self(seeded):
    assert (await call(seeded, ANALYST, "PATCH", "/alerts/med/assignee", {"assignee_id": OTHER_ANALYST["id"]})).status_code == 403
    r = await call(seeded, ANALYST, "PATCH", "/alerts/med/assignee", {"assignee_id": ANALYST["id"]})
    assert r.status_code == 200 and r.json()["assignee_email"] == "l1@corp.local"
    assert (await call(seeded, OTHER_ANALYST, "PATCH", "/alerts/med/assignee", {"assignee_id": None})).status_code == 403
    assert (await call(seeded, MANAGER, "PATCH", "/alerts/med/assignee", {"assignee_id": "u-foreign"})).status_code == 422
    assert (await call(seeded, MANAGER, "PATCH", "/alerts/med/assignee", {"assignee_id": None})).status_code == 200
    assert "assignee_id" not in await seeded["alerts"].find_one({"_id": "med"})


@pytest.mark.asyncio
async def test_queue_filters_and_sorts(seeded):
    await call(seeded, ANALYST, "PATCH", "/alerts/med/assignee", {"assignee_id": ANALYST["id"]})
    mine = (await call(seeded, ANALYST, "GET", "/alerts/?assignee=me")).json()
    assert [a["_id"] for a in mine] == ["med"]
    unassigned = (await call(seeded, ANALYST, "GET", "/alerts/?assignee=unassigned")).json()
    assert [a["_id"] for a in unassigned] == ["crit"]
    by_sev = (await call(seeded, ANALYST, "GET", "/alerts/?sort=severity")).json()
    assert [a["_id"] for a in by_sev] == ["crit", "med"]
    assert by_sev[0]["sla"]["ack_breached"] is True  # critical, 30 min old, never touched
    await call(seeded, MANAGER, "PATCH", "/alerts/crit/disposition", {"action": "suppress", "note": "n"})
    open_ids = [a["_id"] for a in (await call(seeded, ANALYST, "GET", "/alerts/?status=open")).json()]
    assert open_ids == ["med"]


@pytest.mark.asyncio
async def test_bulk_applies_rules_per_alert(seeded):
    r = await call(seeded, ANALYST, "POST", "/alerts/bulk", {
        "alert_ids": ["crit", "med", "med", "foreign"], "action": "close", "verdict": "false_positive", "note": "batch",
    })
    body = r.json()
    assert body["succeeded"] == 1 and body["failed"] == 2
    outcome = {x["alert_id"]: x.get("status_code") for x in body["results"]}
    assert outcome == {"crit": 403, "med": None, "foreign": 404}


@pytest.mark.asyncio
async def test_note_starts_the_acknowledge_clock(seeded):
    r = await call(seeded, ANALYST, "POST", "/alerts/med/notes", {"content": "looking"})
    assert r.status_code == 200
    assert (await seeded["alerts"].find_one({"_id": "med"}))["acknowledged_at"]


def test_sla_breach_is_measured_against_severity_targets():
    fresh = {"severity": "critical", "detected_at": NOW - timedelta(minutes=5)}
    old = {"severity": "critical", "detected_at": NOW - timedelta(minutes=20)}
    acked_in_time = {**old, "acknowledged_at": NOW - timedelta(minutes=10)}
    assert sla_state(fresh, NOW)["ack_breached"] is False
    assert sla_state(old, NOW)["ack_breached"] is True
    assert sla_state(acked_in_time, NOW)["ack_breached"] is False
    assert sla_state({"severity": "weird", "detected_at": NOW}) is None


@pytest.mark.asyncio
async def test_soc_metrics_compute_mtta_mttr_and_precision(seeded):
    await call(seeded, ANALYST, "PATCH", "/alerts/med/disposition", {"action": "close", "verdict": "false_positive", "note": "n"})
    await call(seeded, ANALYST, "PATCH", "/alerts/crit/disposition", {"action": "close", "verdict": "true_positive", "note": "n"})
    m = (await call(seeded, ANALYST, "GET", "/dashboard/soc-metrics", router=dashboard_module.router, prefix="/dashboard")).json()
    assert m["resolved"] == 2 and m["mttr_minutes"] is not None
    assert m["verdicts"] == {"false_positive": 1, "true_positive": 1}
    precision = {r["rule"]: r["precision"] for r in m["rule_precision"]}
    assert precision == {"r1": 1.0, "r2": 0.0}
    assert m["open_by_severity"] == {}


@pytest.mark.asyncio
async def test_user_directory_is_tenant_scoped_and_has_no_secrets(seeded):
    await seeded["users"].update_one({"_id": ANALYST["id"]}, {"$set": {"password_hash": "secret-hash"}})
    r = await call(seeded, ANALYST, "GET", "/users", router=users_module.router, prefix="/users")
    emails = {u["email"] for u in r.json()}
    assert emails == {"l1@corp.local", "l1b@corp.local", "mgr@corp.local"}
    assert "secret-hash" not in r.text


@pytest.mark.asyncio
async def test_api_datetimes_carry_an_explicit_utc_offset(db):
    # Mongo returns naive UTC; without an offset browsers read it as local time.
    await db["alerts"].insert_one({"_id": "naive", "org_id": "acme", "title": "t", "severity": "low", "status": "New",
                                   "created_at": datetime(2026, 10, 1, 12, 0), "detected_at": datetime(2026, 10, 1, 12, 5)})
    listed = (await call(db, ANALYST, "GET", "/alerts/")).json()[0]
    single = (await call(db, ANALYST, "GET", "/alerts/naive")).json()
    for doc in (listed, single):
        assert doc["created_at"] == "2026-10-01T12:00:00+00:00"
        assert doc["detected_at"] == "2026-10-01T12:05:00+00:00"


@pytest.mark.asyncio
async def test_open_high_priority_kpi_counts_investigated_alerts(seeded):
    m = (await call(seeded, ANALYST, "GET", "/dashboard/metrics", router=dashboard_module.router, prefix="/dashboard")).json()
    assert m["high_priority_alerts"] == 1  # "crit" is Investigated, still open
