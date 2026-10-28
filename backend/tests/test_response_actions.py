"""
Production-readiness 2.5 response actions: approval workflow, dry run, execute, rollback, guardrails, audit.
"""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import response as response_module
from app.database.session import get_db
from app.services import response_connectors as rc

ANALYST = {"id": "u1", "email": "l1@corp.local", "role": "soc_analyst", "org_id": "acme"}
MANAGER = {"id": "u2", "email": "mgr@corp.local", "role": "soc_manager", "org_id": "acme"}
MANAGER2 = {"id": "u4", "email": "mgr2@corp.local", "role": "admin", "org_id": "acme"}
FOREIGN = {"id": "ux", "email": "x@other.org", "role": "admin", "org_id": "other"}
REASON = "Host beaconing to known C2, confirmed by analyst"
DEVICE = "a" * 32


@pytest.fixture
def db():
    return AsyncMongoMockClient()["response"]


def settings_for(monkeypatch, live=True, **overrides):
    values = {
        "RESPONSE_LIVE_EXECUTION_ENABLED": live,
        "CROWDSTRIKE_BASE_URL": "https://api.crowdstrike.test", "CROWDSTRIKE_CLIENT_ID": "id", "CROWDSTRIKE_CLIENT_SECRET": "secret",
        "OKTA_BASE_URL": "https://acme.okta.test", "OKTA_API_TOKEN": "tok",
        "FIREWALL_WEBHOOK_URL": "https://fw.gateway.test/hook", "FIREWALL_WEBHOOK_TOKEN": "fwtok",
        "RESPONSE_PROTECTED_TARGETS": "dc01, breakglass@corp.local, 10.0.0.1",
        **overrides,
    }
    for key, value in values.items():
        monkeypatch.setattr(f"app.core.config.settings.{key}", value)


class Remote:
    """Mock of the three target systems; records every request so tests can prove what was (not) sent."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []
        self.device_status = "normal"
        self.okta_status = "ACTIVE"
        self.fail_okta_suspend = False
        self.cs_ids = [DEVICE]
        self.fw_status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except ValueError:
                body = {"form": request.content.decode()}
        self.calls.append((request.method, f"{request.url.host}{request.url.path}", {"params": dict(request.url.params), "body": body}))
        host, path = request.url.host, request.url.path
        if host.startswith("api.crowdstrike"):
            if path == "/oauth2/token":
                return httpx.Response(201, json={"access_token": "cs-token"})
            if path == "/devices/queries/devices/v1":
                return httpx.Response(200, json={"resources": self.cs_ids})
            if path == "/devices/entities/devices/v2":
                return httpx.Response(200, json={"resources": [{"device_id": DEVICE, "hostname": "WS-042", "status": self.device_status, "platform_name": "Windows"}]})
            if path == "/devices/entities/devices-actions/v2":
                self.device_status = "contained" if request.url.params["action_name"] == "contain" else "normal"
                return httpx.Response(202, json={"resources": [{"id": DEVICE}], "errors": []})
        if host.startswith("acme.okta"):
            if request.method == "GET" and path.startswith("/api/v1/users/"):
                if path.endswith("/ghost@corp.local"):
                    return httpx.Response(404)
                return httpx.Response(200, json={"id": "00u1abcdefghijklmnop", "status": self.okta_status, "profile": {"login": "jdoe@corp.local"}})
            if path.endswith("/lifecycle/suspend"):
                if self.fail_okta_suspend:
                    return httpx.Response(500)
                self.okta_status = "SUSPENDED"
                return httpx.Response(200, json={})
            if path.endswith("/lifecycle/unsuspend"):
                self.okta_status = "ACTIVE"
                return httpx.Response(200, json={})
            if path.endswith("/sessions"):
                return httpx.Response(204)
        if host.startswith("fw.gateway"):
            return httpx.Response(self.fw_status, json={"rule_id": "rule-9"} if self.fw_status < 400 else {})
        return httpx.Response(500)


@pytest.fixture
def remote(monkeypatch):
    settings_for(monkeypatch)
    remote = Remote()
    monkeypatch.setattr(rc, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(remote.handler)))
    return remote


async def call(db, user, method, path, json=None, params=None):
    app = FastAPI()
    app.include_router(response_module.router, prefix="/response")

    async def _db():
        return db

    async def _user():
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path, json=json, params=params)


async def request(db, user=ANALYST, action="edr.isolate_host", target="WS-042", reason=REASON, **extra):
    return await call(db, user, "POST", "/response", {"action_type": action, "target": target, "reason": reason, **extra})


async def approved(db, remote_unused=None, **kw):
    created = (await request(db, **kw)).json()
    r = await call(db, MANAGER, "POST", f"/response/{created['id']}/approve", {"note": "ok"})
    assert r.status_code == 200, r.text
    return created["id"]


# ---------- creating requests ----------

@pytest.mark.asyncio
async def test_capabilities_report_what_is_configured_and_whether_live_is_on(db, monkeypatch):
    settings_for(monkeypatch, live=False, OKTA_API_TOKEN="")
    caps = (await call(db, ANALYST, "GET", "/response/capabilities")).json()
    assert caps["live_execution_enabled"] is False
    assert caps["actions"]["edr.isolate_host"]["configured"] is True
    assert caps["actions"]["idp.disable_user"]["configured"] is False
    assert all(a["dry_run"] and a["rollback"] for a in caps["actions"].values())


@pytest.mark.asyncio
async def test_request_validation_and_guardrails(db, remote):
    assert (await request(db, action="host.nuke")).status_code == 422
    assert (await request(db, reason="because")).status_code == 422
    assert (await request(db, target="ws 042; rm -rf")).status_code == 422
    assert (await request(db, action="firewall.block_ip", target="not-an-ip")).status_code == 422
    for bad_ip in ("127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1"):
        assert (await request(db, action="firewall.block_ip", target=bad_ip)).status_code == 422, bad_ip
    assert (await request(db, target="DC01")).status_code == 403  # protected, case-insensitive
    assert (await request(db, action="idp.disable_user", target="breakglass@corp.local")).status_code == 403
    assert (await request(db, action="firewall.block_ip", target="10.0.0.1")).status_code == 403
    assert (await request(db, alert_id="missing")).status_code == 404
    assert (await request(db, incident_id="missing")).status_code == 404
    assert await db["response_requests"].count_documents({}) == 0


@pytest.mark.asyncio
async def test_new_request_waits_for_approval_with_a_read_only_preview_and_no_side_effects(db, remote):
    r = await request(db)
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "pending_approval" and body["requested_by"]["email"] == ANALYST["email"]
    assert body["preview"]["status"] == "ok" and "network-contain" in body["preview"]["summary"]
    assert not any(c[0] == "POST" and c[1].endswith("/devices-actions/v2") for c in remote.calls)
    assert (await request(db)).status_code == 409  # same target already open
    audit = await db["audit_logs"].find_one({"action": "response.requested"})
    assert audit["entity_id"] == body["id"] and audit["metadata"]["target"] == "WS-042"


@pytest.mark.asyncio
async def test_preview_says_so_when_the_connector_is_not_configured(db, monkeypatch):
    settings_for(monkeypatch, CROWDSTRIKE_CLIENT_SECRET="")
    body = (await request(db)).json()
    assert body["preview"]["status"] == "not_configured"


# ---------- approval rules ----------

@pytest.mark.asyncio
async def test_four_eyes_and_roles(db, remote):
    rid = (await request(db, user=MANAGER)).json()["id"]
    assert (await call(db, ANALYST, "POST", f"/response/{rid}/approve", {})).status_code == 403
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/approve", {})).status_code == 403  # own request
    assert (await call(db, FOREIGN, "POST", f"/response/{rid}/approve", {})).status_code == 404  # other tenant
    ok = await call(db, MANAGER2, "POST", f"/response/{rid}/approve", {"note": "seen the EDR detection"})
    assert ok.status_code == 200 and ok.json()["status"] == "approved" and ok.json()["approval"]["by"]["email"] == MANAGER2["email"]
    assert (await call(db, MANAGER2, "POST", f"/response/{rid}/approve", {})).status_code == 409  # already approved
    assert (await call(db, MANAGER2, "POST", f"/response/{rid}/reject", {"note": "x"})).status_code == 200  # approval can still be withdrawn


@pytest.mark.asyncio
async def test_reject_and_cancel(db, remote):
    rid = (await request(db)).json()["id"]
    assert (await call(db, ANALYST, "POST", f"/response/{rid}/reject", {"note": "no"})).status_code == 403
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/reject", {})).status_code == 422  # reason required
    rejected = await call(db, MANAGER, "POST", f"/response/{rid}/reject", {"note": "that host is the build server"})
    assert rejected.json()["status"] == "rejected" and rejected.json()["rejection"]["note"].startswith("that host")
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/approve", {})).status_code == 409
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).status_code == 409

    rid2 = (await request(db, target="WS-043")).json()["id"]
    other = {**ANALYST, "id": "u9", "email": "l1b@corp.local"}
    assert (await call(db, other, "POST", f"/response/{rid2}/cancel")).status_code == 403
    assert (await call(db, ANALYST, "POST", f"/response/{rid2}/cancel")).json()["status"] == "cancelled"
    # With the old request closed, the same target can be requested again.
    assert (await request(db, target="WS-043")).status_code == 201


@pytest.mark.asyncio
async def test_unapproved_requests_expire_and_so_do_unused_approvals(db, remote):
    rid = (await request(db)).json()["id"]
    await db["response_requests"].update_one({"_id": rid}, {"$set": {"requested_at": datetime.now(timezone.utc) - timedelta(hours=25)}})
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/approve", {})).status_code == 409
    assert (await call(db, ANALYST, "GET", f"/response/{rid}")).json()["status"] == "expired"

    rid2 = await approved(db, target="WS-050")
    await db["response_requests"].update_one({"_id": rid2}, {"$set": {"approval.expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}})
    r = await call(db, MANAGER, "POST", f"/response/{rid2}/execute")
    assert r.status_code == 409
    assert (await call(db, ANALYST, "GET", f"/response/{rid2}")).json()["status"] == "expired"
    assert not any(c[0] == "POST" and c[1].endswith("/devices-actions/v2") for c in remote.calls)
    assert await db["audit_logs"].count_documents({"action": "response.expired"}) == 2


# ---------- dry run ----------

@pytest.mark.asyncio
async def test_dry_run_needs_no_approval_and_changes_nothing(db, remote):
    rid = (await request(db)).json()["id"]
    r = await call(db, ANALYST, "POST", f"/response/{rid}/dry-run")
    assert r.status_code == 200 and r.json()["status"] == "pending_approval"
    run = r.json()["executions"][-1]
    assert run["kind"] == "dry_run" and run["ok"] and run["details"]["would_change"] is True
    assert not any(c[0] == "POST" and c[1].endswith("/devices-actions/v2") for c in remote.calls)
    other = {**ANALYST, "id": "u9", "email": "other@corp.local"}
    assert (await call(db, other, "POST", f"/response/{rid}/dry-run")).status_code == 403
    assert (await call(db, FOREIGN, "POST", f"/response/{rid}/dry-run")).status_code == 404

    remote.device_status = "contained"
    again = (await call(db, MANAGER, "POST", f"/response/{rid}/dry-run")).json()["executions"][-1]
    assert again["details"]["would_change"] is False and "already contained" in again["details"]["note"]


@pytest.mark.asyncio
async def test_dry_run_works_even_when_live_execution_is_off_and_reports_missing_targets(db, monkeypatch):
    settings_for(monkeypatch, live=False)
    remote = Remote()
    monkeypatch.setattr(rc, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(remote.handler)))
    rid = (await request(db, action="idp.disable_user", target="ghost@corp.local")).json()["id"]
    run = (await call(db, ANALYST, "POST", f"/response/{rid}/dry-run")).json()["executions"][-1]
    assert run["ok"] is False and "could not find" in run["summary"]


# ---------- execute and roll back ----------

@pytest.mark.asyncio
async def test_execute_requires_approval_and_the_live_switch(db, remote, monkeypatch):
    rid = (await request(db)).json()["id"]
    r = await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    assert r.status_code == 409 and "needs approval" in r.json()["detail"]

    await call(db, MANAGER, "POST", f"/response/{rid}/approve", {})
    monkeypatch.setattr("app.core.config.settings.RESPONSE_LIVE_EXECUTION_ENABLED", False)
    r = await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    assert r.status_code == 409 and "switched off" in r.json()["detail"]
    assert (await call(db, ANALYST, "GET", f"/response/{rid}")).json()["status"] == "approved"  # still usable once enabled

    monkeypatch.setattr("app.core.config.settings.RESPONSE_LIVE_EXECUTION_ENABLED", True)
    other = {**ANALYST, "id": "u9", "email": "other@corp.local"}
    assert (await call(db, other, "POST", f"/response/{rid}/execute")).status_code == 403
    assert not any(c[0] == "POST" and c[1].endswith("/devices-actions/v2") for c in remote.calls)


@pytest.mark.asyncio
async def test_edr_isolate_then_rollback_with_audit_and_incident_timeline(db, remote):
    await db["incidents"].insert_one({"_id": "inc1", "org_id": "acme", "status": "open"})
    rid = await approved(db, incident_id="inc1")
    r = await call(db, ANALYST, "POST", f"/response/{rid}/execute")  # requester may run what was approved
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "succeeded" and body["can_rollback"] and body["executions"][-1]["external_ref"] == DEVICE
    action = next(c for c in remote.calls if c[0] == "POST" and c[1].endswith("/devices-actions/v2"))
    assert action[2]["params"] == {"action_name": "contain"} and action[2]["body"] == {"ids": [DEVICE]}
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).status_code == 409  # not twice

    assert (await call(db, ANALYST, "POST", f"/response/{rid}/rollback", {"note": "x"})).status_code == 403
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {})).status_code == 422
    rolled = await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "false alarm, host is clean"})
    assert rolled.status_code == 200 and rolled.json()["status"] == "rolled_back"
    lift = [c for c in remote.calls if c[0] == "POST" and c[1].endswith("/devices-actions/v2")][-1]
    assert lift[2]["params"] == {"action_name": "lift_containment"}
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "again"})).status_code == 409

    actions = [a["action"] async for a in db["audit_logs"].find({"entity_id": rid}).sort("created_at", 1)]
    assert actions == ["response.requested", "response.approved", "response.executed", "response.rolled_back"]
    kinds = [e["type"] async for e in db["incident_events"].find({"incident_id": "inc1"}).sort("at", 1)]
    assert kinds == ["response_requested", "response_approved", "response_executed", "response_rolled_back"]


@pytest.mark.asyncio
async def test_okta_disable_clears_sessions_and_unsuspend_rolls_back(db, remote):
    rid = await approved(db, action="idp.disable_user", target="jdoe@corp.local")
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).json()["status"] == "succeeded"
    paths = [c[1] for c in remote.calls if c[0] in ("POST", "DELETE")]
    assert paths == ["acme.okta.test/api/v1/users/00u1abcdefghijklmnop/lifecycle/suspend", "acme.okta.test/api/v1/users/00u1abcdefghijklmnop/sessions"]
    assert remote.okta_status == "SUSPENDED"
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "back from leave"})).json()["status"] == "rolled_back"
    assert remote.okta_status == "ACTIVE"
    assert all("SSWS tok" not in json.dumps(c[2]) for c in remote.calls)  # the token is never echoed into stored data


@pytest.mark.asyncio
async def test_failed_execution_is_recorded_and_can_be_retried_while_the_approval_lasts(db, remote):
    rid = await approved(db, action="idp.disable_user", target="jdoe@corp.local")
    remote.fail_okta_suspend = True
    r = await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    assert r.status_code == 200 and r.json()["status"] == "failed" and "HTTP 500" in r.json()["executions"][-1]["summary"]
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "n"})).status_code == 409  # nothing to undo

    remote.fail_okta_suspend = False
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).json()["status"] == "succeeded"
    assert await db["audit_logs"].count_documents({"action": "response.execution_failed", "entity_id": rid}) == 1


@pytest.mark.asyncio
async def test_okta_refuses_a_user_that_is_not_active(db, remote):
    remote.okta_status = "DEPROVISIONED"
    rid = await approved(db, action="idp.disable_user", target="jdoe@corp.local")
    r = (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).json()
    assert r["status"] == "failed" and "DEPROVISIONED" in r["executions"][-1]["summary"]


@pytest.mark.asyncio
async def test_firewall_block_sends_the_documented_payload_and_dry_run_sends_nothing(db, remote):
    rid = await approved(db, action="firewall.block_ip", target="203.0.113.50")
    dry = (await call(db, MANAGER, "POST", f"/response/{rid}/dry-run")).json()["executions"][-1]
    assert dry["ok"] and "no read-only mode" in dry["details"]["note"]
    assert not any(c[1].startswith("fw.gateway") for c in remote.calls)

    done = (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).json()
    assert done["status"] == "succeeded" and done["executions"][-1]["external_ref"] == "rule-9"
    sent = next(c for c in remote.calls if c[1].startswith("fw.gateway"))
    assert sent[2]["body"] == {"action": "block", "indicator": "203.0.113.50", "indicator_type": "ipv4", "reason": REASON, "request_id": rid}
    await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "customer reported outage"})
    assert [c[2]["body"]["action"] for c in remote.calls if c[1].startswith("fw.gateway")] == ["block", "unblock"]


@pytest.mark.asyncio
async def test_rollback_that_fails_leaves_the_action_rollbackable(db, remote):
    rid = await approved(db, action="firewall.block_ip", target="203.0.113.51")
    await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    remote.fw_status = 502
    r = await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "n"})
    assert r.status_code == 502
    stored = (await call(db, MANAGER, "GET", f"/response/{rid}")).json()
    assert stored["status"] == "succeeded" and stored["executions"][-1]["kind"] == "rollback" and stored["executions"][-1]["ok"] is False
    remote.fw_status = 200
    assert (await call(db, MANAGER, "POST", f"/response/{rid}/rollback", {"note": "retry"})).json()["status"] == "rolled_back"


@pytest.mark.asyncio
async def test_ambiguous_hostname_is_refused_rather_than_guessed(db, remote):
    remote.cs_ids = [DEVICE, "b" * 32]
    rid = await approved(db)
    r = (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).json()
    assert r["status"] == "failed" and "More than one" in r["executions"][-1]["summary"]
    assert not any(c[0] == "POST" and c[1].endswith("/devices-actions/v2") for c in remote.calls)


@pytest.mark.asyncio
async def test_circuit_breaker_stops_a_runaway_number_of_live_actions(db, remote, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.RESPONSE_MAX_LIVE_PER_HOUR", 2)
    for i in range(2):
        rid = await approved(db, action="firewall.block_ip", target=f"203.0.113.{60 + i}")
        assert (await call(db, MANAGER, "POST", f"/response/{rid}/execute")).json()["status"] == "succeeded"
    rid = await approved(db, action="firewall.block_ip", target="203.0.113.99")
    r = await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    assert r.status_code == 429 and "Circuit breaker" in r.json()["detail"]
    assert (await call(db, ANALYST, "GET", f"/response/{rid}")).json()["status"] == "approved"


@pytest.mark.asyncio
async def test_protected_list_is_rechecked_at_execution_time(db, remote, monkeypatch):
    rid = await approved(db, target="WS-777")
    monkeypatch.setattr("app.core.config.settings.RESPONSE_PROTECTED_TARGETS", "ws-777")
    r = await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    assert r.status_code == 403
    assert not any(c[0] == "POST" and c[1].endswith("/devices-actions/v2") for c in remote.calls)


@pytest.mark.asyncio
async def test_execute_without_a_configured_connector_is_refused_not_faked(db, monkeypatch):
    settings_for(monkeypatch, OKTA_API_TOKEN="")
    rid = await approved(db, action="idp.disable_user", target="jdoe@corp.local")
    r = await call(db, MANAGER, "POST", f"/response/{rid}/execute")
    assert r.status_code == 503 and "not configured" in r.json()["detail"]


@pytest.mark.asyncio
async def test_listing_is_tenant_scoped_and_filterable(db, remote):
    await request(db)
    await request(db, user={**ANALYST, "org_id": "other", "id": "uz"}, target="WS-900")
    rows = (await call(db, ANALYST, "GET", "/response")).json()
    assert [r["target"] for r in rows] == ["WS-042"]
    assert (await call(db, ANALYST, "GET", "/response", params={"status": "approved"})).json() == []
    assert (await call(db, ANALYST, "GET", "/response", params={"status": "bogus"})).status_code == 422


@pytest.mark.asyncio
async def test_asking_for_approval_does_not_fail_when_no_notification_channel_exists(db, remote, caplog):
    # Regression: the "no channels" log line used a reserved keyword and raised, which also aborted SLA sweeps.
    from app.services.notifications import NotificationEventType, NotificationPayload
    from app.services.sla_monitor import notify_all_channels

    await notify_all_channels(db, NotificationPayload(event_type=NotificationEventType.RESPONSE_APPROVAL_REQUESTED, alert_id="x", title="t", severity="high"), "acme")
    assert (await request(db)).status_code == 201
    assert "response_notify_failed" not in caplog.text
