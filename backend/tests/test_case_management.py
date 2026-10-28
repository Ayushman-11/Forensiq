"""
Production-readiness 2.4 case management: incident status/owner/notes/timeline, merge/split/pin,
external tickets, per-tenant SLA targets and the escalation policy.
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.api.v1.endpoints import incidents as incidents_module
from app.api.v1.endpoints import policies as policies_module
from app.database.session import get_db
from app.services import ticketing
from app.services.cases import sync_all_tickets
from app.services.incidents import link_alerts, rebuild_incidents
from app.services.sla import get_sla_targets
from app.services.sla_monitor import SLAEscalationMonitor
from app.services.triage import sla_state

T0 = datetime(2026, 10, 1, 12, 0)
NOW = datetime.now(timezone.utc)
ANALYST = {"id": "u1", "email": "l1@corp.local", "role": "soc_analyst", "org_id": "acme"}
OTHER = {"id": "u3", "email": "l1b@corp.local", "role": "soc_analyst", "org_id": "acme"}
MANAGER = {"id": "u2", "email": "mgr@corp.local", "role": "soc_manager", "org_id": "acme"}
FOREIGN = {"id": "ux", "email": "x@other.org", "role": "soc_manager", "org_id": "other"}


def alert(i, host="h1", user="CORP\\alice", minutes=0, severity="high", org="acme", status="New", **kw):
    return {"_id": f"a{i}", "org_id": org, "title": f"alert {i}", "host": host, "user": user, "severity": severity,
            "rule_name": f"r{i}", "status": status, "first_seen": T0 + timedelta(minutes=minutes),
            "created_at": T0 + timedelta(minutes=minutes), "extracted_iocs": [], **kw}


@pytest.fixture
def db():
    return AsyncMongoMockClient()["cases"]


@pytest.fixture
async def seeded(db):
    await db["users"].insert_many([
        {"_id": u["id"], "email": u["email"], "role": u["role"], "org_id": "acme", "is_active": True} for u in (ANALYST, OTHER, MANAGER)
    ] + [{"_id": "ux", "email": "x@other.org", "role": "soc_manager", "org_id": "other", "is_active": True}])
    alerts = [alert(1, host="h1", user="u1"), alert(2, host="h1", user="u2", minutes=5),
              alert(3, host="h2", user="u3", minutes=10), alert(4, host="h3", user="u4", minutes=20)]
    await db["alerts"].insert_many([dict(a) for a in alerts])
    await link_alerts(db, alerts)
    return db


async def call(db, user, method, path, json=None, params=None, router=incidents_module.router, prefix="/incidents"):
    app = FastAPI()
    app.include_router(router, prefix=prefix)

    async def _db():
        return db

    async def _user():
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path, json=json, params=params)


async def incident_of(db, alert_id):
    return (await db["alerts"].find_one({"_id": alert_id}))["incident_id"]


# ---------- status, owner, notes, timeline ----------

@pytest.mark.asyncio
async def test_incident_has_its_own_status_and_closing_needs_a_note_and_no_open_alerts(seeded):
    db = seeded
    inc = await incident_of(db, "a1")
    detail = (await call(db, ANALYST, "GET", f"/incidents/{inc}")).json()
    assert detail["status"] == "open" and detail["case_owner"] is None

    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "in_progress"})
    assert r.status_code == 200
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "bogus"})).status_code == 422
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "resolved"})).status_code == 422  # no note
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "resolved", "note": "done"})
    assert r.status_code == 409 and "still open" in r.json()["detail"]  # member alerts are open
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "resolved", "note": "done", "force": True})
    assert r.status_code == 409  # analysts cannot force
    r = await call(db, MANAGER, "POST", f"/incidents/{inc}/status", {"status": "resolved", "note": "benign admin work", "force": True})
    assert r.status_code == 200

    stored = await db["incidents"].find_one({"_id": inc})
    assert stored["status"] == "resolved" and stored["resolution_note"] == "benign admin work" and stored["resolved_by"] == MANAGER["email"]
    reopened = await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "open"})
    assert reopened.status_code == 200
    assert "resolved_at" not in await db["incidents"].find_one({"_id": inc})
    assert await db["audit_logs"].count_documents({"entity_type": "incident", "entity_id": inc, "action": "incident.status_changed"}) == 3


@pytest.mark.asyncio
async def test_owner_rules_mirror_alert_assignment(seeded):
    db = seeded
    inc = await incident_of(db, "a1")
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/owner", {"owner_id": "u3"})).status_code == 403
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/owner", {"owner_id": "ux"})).status_code == 403
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/owner", {"owner_id": "u1"})).json()["owner_email"] == ANALYST["email"]
    assert (await call(db, OTHER, "POST", f"/incidents/{inc}/owner", {"owner_id": None})).status_code == 403  # not theirs to release
    assert (await call(db, MANAGER, "POST", f"/incidents/{inc}/owner", {"owner_id": "u3"})).status_code == 200
    assert (await call(db, MANAGER, "POST", f"/incidents/{inc}/owner", {"owner_id": "ux"})).status_code == 422  # other tenant
    detail = (await call(db, ANALYST, "GET", f"/incidents/{inc}")).json()
    assert detail["case_owner"] == OTHER["email"]


@pytest.mark.asyncio
async def test_notes_and_timeline_combine_case_events_and_detections(seeded):
    db = seeded
    inc = await incident_of(db, "a1")
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/notes", {"content": "   "})).status_code == 422
    note = await call(db, ANALYST, "POST", f"/incidents/{inc}/notes", {"content": "Checked EDR, host is a build server"})
    assert note.status_code == 201
    await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "in_progress"})

    notes = (await call(db, ANALYST, "GET", f"/incidents/{inc}/notes")).json()
    assert [n["content"] for n in notes] == ["Checked EDR, host is a build server"]
    timeline = (await call(db, ANALYST, "GET", f"/incidents/{inc}/timeline")).json()
    kinds = [e["type"] for e in timeline]
    assert kinds.count("alert_detected") == 2 and "note_added" in kinds and "status_changed" in kinds
    assert kinds[0] == "alert_detected"  # oldest first
    assert all(e["at"].endswith("+00:00") for e in timeline)


@pytest.mark.asyncio
async def test_other_tenants_cannot_touch_an_incident(seeded):
    db = seeded
    inc = await incident_of(db, "a1")
    for method, path, body in [("GET", f"/incidents/{inc}/timeline", None), ("GET", f"/incidents/{inc}/notes", None),
                               ("POST", f"/incidents/{inc}/notes", {"content": "x"}),
                               ("POST", f"/incidents/{inc}/status", {"status": "in_progress"}),
                               ("POST", f"/incidents/{inc}/pin", {"alert_id": "a1"})]:
        assert (await call(db, FOREIGN, method, path, body)).status_code == 404, path


# ---------- merge / split / pin ----------

@pytest.mark.asyncio
async def test_manual_merge_moves_alerts_notes_and_tickets(seeded):
    db = seeded
    a, b = await incident_of(db, "a1"), await incident_of(db, "a3")
    assert a != b
    await call(db, ANALYST, "POST", f"/incidents/{b}/notes", {"content": "note on B"})
    assert (await call(db, ANALYST, "POST", f"/incidents/{a}/merge", {"source_ids": [b], "note": ""})).status_code == 422
    r = await call(db, ANALYST, "POST", f"/incidents/{a}/merge", {"source_ids": [b, a], "note": "same intrusion set"})
    assert r.status_code == 200 and r.json()["merged"] == [b]

    assert await db["incidents"].count_documents({"_id": b}) == 0
    assert await incident_of(db, "a3") == a
    merged = await db["incidents"].find_one({"_id": a})
    assert merged["alert_count"] == 3 and merged["manual"] is True and merged["merged_from"] == [b]
    assert sorted(merged["hosts"]) == ["h1", "h2"]
    notes = (await call(db, ANALYST, "GET", f"/incidents/{a}/notes")).json()
    assert [n["content"] for n in notes] == ["note on B"]
    assert (await call(db, ANALYST, "POST", f"/incidents/{a}/merge", {"source_ids": ["missing"], "note": "x"})).status_code == 404
    assert (await call(db, FOREIGN, "POST", f"/incidents/{a}/merge", {"source_ids": [b], "note": "x"})).status_code == 404


@pytest.mark.asyncio
async def test_split_creates_a_new_incident_and_regroup_respects_it(seeded):
    db = seeded
    inc = await incident_of(db, "a1")
    assert inc == await incident_of(db, "a2")
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/split", {"alert_ids": ["a1", "a2"], "note": "n"})).status_code == 422  # would empty it
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/split", {"alert_ids": ["a3"], "note": "n"})).status_code == 422  # not a member
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/split", {"alert_ids": ["a2"], "title": "Lateral movement", "note": "different actor"})
    assert r.status_code == 200
    new_id = r.json()["new_incident_id"]
    assert await incident_of(db, "a1") == inc and await incident_of(db, "a2") == new_id
    assert (await db["incidents"].find_one({"_id": inc}))["alert_count"] == 1
    new = (await call(db, ANALYST, "GET", f"/incidents/{new_id}")).json()
    assert new["title"] == "Lateral movement" and new["split_from"] == inc and new["pinned_alert_ids"] == ["a2"]

    # A full regroup would re-join a1 and a2 (same host); the manual split must survive it.
    await rebuild_incidents(db, "acme")
    assert await incident_of(db, "a1") != await incident_of(db, "a2")
    assert await db["incidents"].find_one({"_id": new_id}) is not None


@pytest.mark.asyncio
async def test_pin_moves_an_alert_and_drops_the_emptied_incident(seeded):
    db = seeded
    a, c = await incident_of(db, "a1"), await incident_of(db, "a4")
    r = await call(db, ANALYST, "POST", f"/incidents/{a}/pin", {"alert_id": "a4"})
    assert r.status_code == 200 and r.json()["previous_incident_id"] == c
    assert await incident_of(db, "a4") == a and (await db["alerts"].find_one({"_id": "a4"}))["incident_pinned"] is True
    assert await db["incidents"].count_documents({"_id": c}) == 0  # only member left: gone
    assert (await db["incidents"].find_one({"_id": a}))["alert_count"] == 3

    await rebuild_incidents(db, "acme")
    assert await incident_of(db, "a4") == a  # pinned alert stays
    assert (await call(db, ANALYST, "POST", f"/incidents/{a}/pin", {"alert_id": "nope"})).status_code == 404

    assert (await call(db, ANALYST, "DELETE", f"/incidents/{a}/pin/a4")).status_code == 200
    assert (await call(db, ANALYST, "DELETE", f"/incidents/{a}/pin/a4")).status_code == 404
    assert any(e["type"] == "alert_pinned" for e in (await call(db, ANALYST, "GET", f"/incidents/{a}/timeline")).json())


@pytest.mark.asyncio
async def test_automatic_grouping_joins_but_never_absorbs_a_manual_incident(seeded):
    db = seeded
    a = await incident_of(db, "a1")
    await call(db, ANALYST, "POST", f"/incidents/{a}/pin", {"alert_id": "a3"})  # a is now manual
    newcomer = alert(9, host="h1", user="u9", minutes=30)
    await db["alerts"].insert_one(dict(newcomer))
    await link_alerts(db, [newcomer])
    assert await incident_of(db, "a9") == a
    assert await db["incidents"].count_documents({"_id": a}) == 1


# ---------- external tickets ----------

def _mock_jira(monkeypatch, state):
    monkeypatch.setattr("app.services.ticketing.settings.JIRA_BASE_URL", "https://acme.atlassian.net")
    monkeypatch.setattr("app.services.ticketing.settings.JIRA_EMAIL", "bot@acme.test")
    monkeypatch.setattr("app.services.ticketing.settings.JIRA_API_TOKEN", "tok")
    monkeypatch.setattr("app.services.ticketing.settings.JIRA_PROJECT_KEY", "SEC")
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path.startswith("/rest/api/3/issue/"):
            if request.url.path.endswith("MISSING-1"):
                return httpx.Response(404)
            return httpx.Response(200, json={"fields": {"summary": "s", "status": {"name": state["name"], "statusCategory": {"key": state["category"]}}}})
        if request.method == "POST" and request.url.path == "/rest/api/3/issue":
            return httpx.Response(201, json={"key": "SEC-77"})
        if request.method == "POST" and request.url.path.endswith("/comment"):
            return httpx.Response(201, json={})
        return httpx.Response(500)

    monkeypatch.setattr(ticketing, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return calls


@pytest.mark.asyncio
async def test_link_validates_keys_and_works_unconfigured_without_pretending_to_sync(seeded):
    db = seeded
    inc = await incident_of(db, "a1")
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "key": "not a key"})).status_code == 422
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "pagerduty", "key": "X-1"})).status_code == 422
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "create": True})).status_code == 503
    linked = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "key": "sec-12"})
    assert linked.status_code == 201
    ticket = linked.json()
    assert ticket["key"] == "SEC-12" and ticket["sync_state"] == "not_configured" and "sys_id" not in ticket
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "key": "SEC-12"})).status_code == 409
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets/{ticket['id']}/sync")).status_code == 503
    assert (await call(db, ANALYST, "DELETE", f"/incidents/{inc}/tickets/{ticket['id']}")).status_code == 200
    assert (await db["incidents"].find_one({"_id": inc}))["tickets"] == []


@pytest.mark.asyncio
async def test_jira_create_link_sync_and_status_follows_the_ticket(seeded, monkeypatch):
    db = seeded
    state = {"name": "To Do", "category": "new"}
    calls = _mock_jira(monkeypatch, state)
    inc = await incident_of(db, "a1")

    created = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "create": True})
    assert created.status_code == 201 and created.json()["key"] == "SEC-77" and created.json()["created_by_forensiq"] is True
    assert created.json()["url"] == "https://acme.atlassian.net/browse/SEC-77"
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "key": "MISSING-1"})).status_code == 404
    tid = created.json()["id"]

    state.update(name="In Progress", category="indeterminate")
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets/{tid}/sync")
    assert r.json()["mapped_status"] == "in_progress" and r.json()["applied_status"] == "in_progress"
    assert (await db["incidents"].find_one({"_id": inc}))["status"] == "in_progress"

    state.update(name="Done", category="done")
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets/{tid}/sync", params={"apply": "false"})
    assert r.json()["applied_status"] is None and (await db["incidents"].find_one({"_id": inc}))["status"] == "in_progress"
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets/{tid}/sync")
    assert r.json()["applied_status"] == "resolved"
    resolved = await db["incidents"].find_one({"_id": inc})
    assert resolved["status"] == "resolved" and "SEC-77" in resolved["resolution_note"]
    assert any(e["type"] == "ticket_synced" for e in (await call(db, ANALYST, "GET", f"/incidents/{inc}/timeline")).json())

    # Our own status changes are mirrored to the ticket as a comment, best effort.
    await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "open"})
    assert ("POST", "/rest/api/3/issue/SEC-77/comment") in calls


@pytest.mark.asyncio
async def test_unreachable_ticket_system_is_reported_and_does_not_break_case_actions(seeded, monkeypatch):
    db = seeded
    state = {"name": "To Do", "category": "new"}
    _mock_jira(monkeypatch, state)
    inc = await incident_of(db, "a1")
    tid = (await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "jira", "create": True})).json()["id"]

    def boom():
        raise httpx.ConnectError("down")

    class Down(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise httpx.ConnectError("down")

    monkeypatch.setattr(ticketing, "_client", lambda: httpx.AsyncClient(transport=Down()))
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets/{tid}/sync")
    assert r.status_code == 502 and "unreachable" in r.json()["detail"]
    stored = (await db["incidents"].find_one({"_id": inc}))["tickets"][0]
    assert stored["sync_state"] == "error"
    assert (await call(db, ANALYST, "POST", f"/incidents/{inc}/status", {"status": "in_progress"})).status_code == 200  # comment failure is swallowed


@pytest.mark.asyncio
async def test_servicenow_status_mapping_and_background_sync(seeded, monkeypatch):
    db = seeded
    monkeypatch.setattr("app.services.ticketing.settings.SERVICENOW_INSTANCE_URL", "https://acme.service-now.com")
    monkeypatch.setattr("app.services.ticketing.settings.SERVICENOW_USER", "svc")
    monkeypatch.setattr("app.services.ticketing.settings.SERVICENOW_PASSWORD", "pw")
    state = {"state": "1"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": [{"sys_id": "abc", "number": "INC0010001", "state": state["state"], "short_description": "x"}]})

    monkeypatch.setattr(ticketing, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    inc = await incident_of(db, "a1")
    r = await call(db, ANALYST, "POST", f"/incidents/{inc}/tickets", {"system": "servicenow", "key": "INC0010001"})
    assert r.status_code == 201 and r.json()["mapped_status"] == "open"

    state["state"] = "6"
    assert await sync_all_tickets(db) == 1
    assert (await db["incidents"].find_one({"_id": inc}))["status"] == "resolved"
    assert await sync_all_tickets(db) == 0  # resolved incidents are no longer polled


# ---------- per-tenant SLA targets ----------

@pytest.mark.asyncio
async def test_sla_targets_are_configurable_per_tenant_validated_and_audited(db):
    assert (await get_sla_targets(db, "acme"))["critical"] == (15, 240)  # built-in default

    r = await call(db, ANALYST, "PUT", "/policies/sla", {"content": {"critical": [5, 60]}, "reason": "stricter"}, router=policies_module.router, prefix="/policies")
    assert r.status_code == 403
    bad = [{"critical": [60, 30]}, {"critical": [0, 5]}, {"urgent": [1, 2]}, {"critical": "fast"}]
    for content in bad:
        r = await call(db, MANAGER, "PUT", "/policies/sla", {"content": content, "reason": "x"}, router=policies_module.router, prefix="/policies")
        assert r.status_code == 422, content
    r = await call(db, MANAGER, "PUT", "/policies/sla", {"content": {"critical": [5, 60]}, "reason": "board asked for tighter SLAs"},
                   router=policies_module.router, prefix="/policies")
    assert r.status_code == 200 and r.json()["version"] == 1

    assert (await get_sla_targets(db, "acme"))["critical"] == (5, 60)
    assert (await get_sla_targets(db, "acme"))["high"] == (60, 24 * 60)  # unspecified severities keep defaults
    assert (await get_sla_targets(db, "other"))["critical"] == (15, 240)  # other tenants unaffected
    shown = await call(db, ANALYST, "GET", "/policies/sla", router=policies_module.router, prefix="/policies")
    assert shown.json()["critical"] == {"ack_minutes": 5, "resolve_minutes": 60}
    assert await db["audit_logs"].count_documents({"action": "policy.updated", "entity_id": "sla_targets"}) == 1

    breached = {"severity": "critical", "detected_at": NOW - timedelta(minutes=10)}
    assert sla_state(breached)["ack_breached"] is False
    assert sla_state(breached, targets_by_severity=await get_sla_targets(db, "acme"))["ack_breached"] is True


@pytest.mark.asyncio
async def test_alert_api_uses_the_tenants_sla_targets(db):
    await db["alerts"].insert_one({"_id": "c1", "org_id": "acme", "title": "c", "severity": "critical", "status": "New", "detected_at": NOW - timedelta(minutes=10)})
    before = (await call(db, ANALYST, "GET", "/alerts/c1", router=alerts_module.router, prefix="/alerts")).json()
    assert before["sla"]["ack_breached"] is False
    await call(db, MANAGER, "PUT", "/policies/sla", {"content": {"critical": [5, 60]}, "reason": "tighten"}, router=policies_module.router, prefix="/policies")
    after = (await call(db, ANALYST, "GET", "/alerts/c1", router=alerts_module.router, prefix="/alerts")).json()
    assert after["sla"]["ack_breached"] is True


# ---------- escalation policy ----------

def _sink(monkeypatch):
    sent = []

    async def fake_notify(db, payload, org_id="default"):
        sent.append((payload.event_type.value, payload.alert_id, org_id))

    monkeypatch.setattr("app.services.sla_monitor.notify_all_channels", fake_notify)
    return sent


@pytest.mark.asyncio
async def test_escalation_policy_validation_and_reassign_target_must_be_an_active_tenant_user(seeded):
    db = seeded
    put = lambda user, content: call(db, user, "PUT", "/policies/escalation", {"content": content, "reason": "policy"}, router=policies_module.router, prefix="/policies")
    assert (await put(ANALYST, {})).status_code == 403
    assert (await put(MANAGER, {"critical": {"nope": {}}})).status_code == 422
    assert (await put(MANAGER, {"critical": {"ack_breach": {"shout": True}}})).status_code == 422
    assert (await put(MANAGER, {"critical": {"ack_breach": {"reassign_to": "ux"}}})).status_code == 422  # other tenant's user
    ok = await put(MANAGER, {"critical": {"ack_breach": {"reassign_to": "u2"}}})
    assert ok.status_code == 200
    shown = (await call(db, ANALYST, "GET", "/policies/escalation", router=policies_module.router, prefix="/policies")).json()
    assert shown["critical"]["ack_breach"]["reassign_to"] == "u2" and shown["critical"]["ack_breach"]["notify"] is True
    assert shown["low"]["resolve_breach"]["mark_escalated"] is False


@pytest.mark.asyncio
async def test_monitor_notifies_reassigns_and_escalates_once_per_policy(db, monkeypatch):
    sent = _sink(monkeypatch)
    await db["users"].insert_many([{"_id": "u2", "email": MANAGER["email"], "role": "soc_manager", "org_id": "acme", "is_active": True}])
    await db["alerts"].insert_many([
        {"_id": "crit", "org_id": "acme", "title": "c", "severity": "critical", "status": "New", "detected_at": NOW - timedelta(minutes=20)},
        {"_id": "fresh", "org_id": "acme", "title": "f", "severity": "critical", "status": "New", "detected_at": NOW - timedelta(minutes=1)},
        {"_id": "foreign", "org_id": "other", "title": "o", "severity": "low", "status": "New", "detected_at": NOW - timedelta(minutes=5)},
    ])
    await call(db, MANAGER, "PUT", "/policies/escalation",
               {"content": {"critical": {"ack_breach": {"reassign_to": "u2", "mark_escalated": True}}}, "reason": "page the on-call manager"},
               router=policies_module.router, prefix="/policies")
    monitor = SLAEscalationMonitor(db)

    assert await monitor.check_alerts_sla(NOW) == 1  # default critical ack target is 15m
    crit = await db["alerts"].find_one({"_id": "crit"})
    assert crit["assignee_id"] == "u2" and crit["status"] == "Escalated" and crit["notified_sla_ack_breach"] is True
    assert ("sla_ack_breach", "crit", "acme") in sent and ("alert_escalated", "crit", "acme") in sent
    assert not any(alert_id in ("fresh", "foreign") for _, alert_id, _ in sent if _ != "unassigned_critical")
    audit = await db["audit_logs"].find_one({"action": "alert.sla_ack_breach", "entity_id": "crit"})
    assert audit["metadata"]["reassigned_to"] == "u2" and audit["actor_email"] == "sla-monitor@forensiq"

    assert await monitor.check_alerts_sla(NOW) == 0  # once only
    assert sent.count(("sla_ack_breach", "crit", "acme")) == 1


@pytest.mark.asyncio
async def test_monitor_follows_tenant_sla_targets_and_can_be_told_not_to_notify(db, monkeypatch):
    sent = _sink(monkeypatch)
    await db["alerts"].insert_one({"_id": "m1", "org_id": "acme", "title": "m", "severity": "medium", "status": "New", "detected_at": NOW - timedelta(minutes=30)})
    monitor = SLAEscalationMonitor(db)
    assert await monitor.check_alerts_sla(NOW) == 0  # medium default ack is 4h

    await call(db, MANAGER, "PUT", "/policies/sla", {"content": {"medium": [10, 120]}, "reason": "tighter"}, router=policies_module.router, prefix="/policies")
    await call(db, MANAGER, "PUT", "/policies/escalation", {"content": {"medium": {"ack_breach": {"notify": False}}}, "reason": "quiet"},
               router=policies_module.router, prefix="/policies")
    assert await monitor.check_alerts_sla(NOW) == 1
    assert sent == []  # breach recorded and audited, but policy says do not page anyone
    assert (await db["alerts"].find_one({"_id": "m1"}))["sla_ack_breached"] is True


@pytest.mark.asyncio
async def test_monitor_survives_a_reassign_target_that_went_inactive(db, monkeypatch):
    _sink(monkeypatch)
    await db["users"].insert_one({"_id": "gone", "email": "gone@corp.local", "role": "soc_manager", "org_id": "acme", "is_active": False})
    await db["policies"].insert_one({"_id": "p", "org_id": "acme", "policy_type": "escalation", "version": 1, "is_active": True,
                                     "content": {"critical": {"ack_breach": {"reassign_to": "gone"}}}})
    await db["alerts"].insert_one({"_id": "c", "org_id": "acme", "title": "c", "severity": "critical", "status": "New", "detected_at": NOW - timedelta(minutes=30)})
    assert await SLAEscalationMonitor(db).check_alerts_sla(NOW) == 1
    audit = await db["audit_logs"].find_one({"action": "alert.sla_ack_breach"})
    assert "reassign_failed" in audit["metadata"] and "assignee_id" not in await db["alerts"].find_one({"_id": "c"})
