"""
Production-readiness 2.7: outbound events, signed webhooks with retries, and the pull feed.
"""

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import integrations as integrations_module
from app.core.security import create_access_token
from app.database.session import get_db
from app.main import app
from app.services import events as ev
from app.services.audit import record_audit
from app.services.ingestion import IngestionService
from tests.test_elastic_siem import SYSMON_PROCESS, client_with

ADMIN = {"id": "u-admin", "email": "admin@acme.example", "role": "admin", "org_id": "acme"}
GLOBEX_ADMIN = {"id": "u-g", "email": "admin@globex.example", "role": "admin", "org_id": "globex"}
ANALYST = {"id": "u-an", "email": "l1@acme.example", "role": "soc_analyst", "org_id": "acme"}


@pytest.fixture
async def db(monkeypatch):
    database = AsyncMongoMockClient()["hooks"]
    for u in (ADMIN, GLOBEX_ADMIN, ANALYST):
        await database["users"].insert_one({"_id": u["id"], "email": u["email"], "role": u["role"], "org_id": u["org_id"], "is_active": True})

    async def _db():
        return database

    async def resolves_publicly(url):  # no DNS in tests
        parsed = ev.urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("webhook URL must be https")

    monkeypatch.setattr(ev, "assert_deliverable", resolves_publicly)
    app.dependency_overrides[get_db] = _db
    yield database
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
async def client(db):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


def human(user=ADMIN):
    return {"Authorization": "Bearer " + create_access_token(user_id=user["id"], email=user["email"], role=user["role"], org_id=user["org_id"])}


class Receiver:
    """Stands in for the customer's endpoint and records what it was sent."""

    def __init__(self, monkeypatch, status=200):
        self.status, self.requests = status, []
        monkeypatch.setattr(ev, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(self.handle)))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status)


async def new_hook(client, db, events=("*",), url="https://soar.acme.example/hook", user=ADMIN):
    r = await client.post("/api/v1/integrations/webhooks", json={"name": "SOAR", "url": url, "events": list(events)}, headers=human(user))
    assert r.status_code == 201, r.text
    # Creating a webhook is itself an audited action, so a "*" subscription is sent its own creation event.
    # Tests that count deliveries start from an empty queue.
    await db["webhook_deliveries"].delete_many({})
    return r.json()


async def audit(db, action="alert.close", org="acme", entity="a-1"):
    return await record_audit(db, {"id": "u1", "email": "analyst@acme.example", "org_id": org}, action, "alert", entity, {"note": "done"})


# ---------- events ----------

@pytest.mark.asyncio
async def test_every_audited_action_becomes_a_tenant_scoped_numbered_event(db):
    await audit(db, "alert.close", "acme")
    await audit(db, "alert.escalate", "acme", "a-2")
    await audit(db, "alert.close", "globex", "g-1")
    await record_audit(db, {"id": "u1", "email": "x@acme.example", "org_id": "acme"}, "search.execute", "search", "splunk", {"query": "index=main password"})
    acme = [e async for e in db["outbound_events"].find({"org_id": "acme"}).sort("seq", 1)]
    assert [(e["seq"], e["type"]) for e in acme] == [(1, "alert.close"), (2, "alert.escalate")]  # search.* is excluded; numbering is per tenant
    assert acme[0]["data"] == {"audit_id": acme[0]["data"]["audit_id"], "entity_type": "alert", "entity_id": "a-1", "actor_email": "analyst@acme.example", "metadata": {"note": "done"}}
    assert [e["seq"] async for e in db["outbound_events"].find({"org_id": "globex"})] == [1]


@pytest.mark.asyncio
async def test_a_failing_event_pipeline_never_fails_the_audited_action(db, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("queue down")

    monkeypatch.setattr(ev, "emit_event", boom)
    entry = await audit(db)
    assert entry["action"] == "alert.close" and await db["audit_logs"].count_documents({}) == 1


@pytest.mark.asyncio
async def test_new_alerts_from_ingestion_emit_alert_created(db):
    def handler(request):
        if request.url.path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "p"})
        if request.url.path == "/_search":
            return httpx.Response(200, json={"hits": {"hits": [SYSMON_PROCESS]}})
        return httpx.Response(200, json={})

    await IngestionService(db, "acme", splunk_factory=lambda: client_with(handler), detection_index="w-*").fetch_and_store_alerts()
    event = await db["outbound_events"].find_one({"org_id": "acme", "type": "alert.created"})
    assert event["data"]["rule_name"] == "suspicious_powershell_execution" and event["data"]["host"] == "WS-042" and event["data"]["severity"]


def test_event_patterns():
    assert ev.matches(["*"], "alert.close") and ev.matches(["alert.*"], "alert.close") and ev.matches(["alert.close"], "alert.close")
    assert not ev.matches(["alert.*"], "incident.merged") and not ev.matches(["alert.close"], "alert.closed") and not ev.matches([], "alert.close")
    assert ev.validate_patterns(["Alert.*", "alert.*", "*"]) == ["alert.*", "*"]
    for bad in ([], ["alert"], ["alert.*.x"], ["../x"], ["a.b", "c.d.e"], ["x"] * 21):
        with pytest.raises(ValueError):
            ev.validate_patterns(bad)


# ---------- pull feed ----------

@pytest.mark.asyncio
async def test_the_feed_returns_events_in_order_exactly_once_per_cursor(client, db):
    for i in range(5):
        await audit(db, "alert.close" if i % 2 == 0 else "incident.merged", entity=f"e{i}")
    await audit(db, "alert.close", org="globex")
    first = (await client.get("/api/v1/events", params={"limit": 2}, headers=human())).json()
    assert [e["seq"] for e in first["events"]] == [1, 2] and first["next_cursor"] == 2 and first["events"][0]["tenant"] == "acme"
    second = (await client.get("/api/v1/events", params={"after": first["next_cursor"], "limit": 10}, headers=human())).json()
    assert [e["seq"] for e in second["events"]] == [3, 4, 5] and second["next_cursor"] == 5
    assert (await client.get("/api/v1/events", params={"after": 5}, headers=human())).json() == {"events": [], "next_cursor": 5}  # idle poll keeps its cursor
    only = (await client.get("/api/v1/events", params={"type": "incident.*"}, headers=human())).json()
    assert [e["type"] for e in only["events"]] == ["incident.merged", "incident.merged"] and only["next_cursor"] == 5
    assert all(e["tenant"] == "globex" for e in (await client.get("/api/v1/events", headers=human(GLOBEX_ADMIN))).json()["events"])
    assert (await client.get("/api/v1/events", params={"limit": 0}, headers=human())).status_code == 422
    assert (await client.get("/api/v1/events")).status_code == 401


# ---------- webhook management ----------

@pytest.mark.asyncio
async def test_creating_a_webhook_shows_the_secret_once_and_stores_it_encrypted(client, db):
    hook = await new_hook(client, db, events=["alert.*", "incident.merged"])
    secret = hook["secret"]
    assert secret.startswith("whsec_") and hook["events"] == ["alert.*", "incident.merged"] and hook["enabled"]
    stored = await db["webhook_subscriptions"].find_one({"_id": hook["id"]})
    assert stored["secret_enc"].startswith("enc:v1:") and secret not in str(stored)
    for response in ((await client.get("/api/v1/integrations/webhooks", headers=human())).text, (await client.get(f"/api/v1/integrations/webhooks/{hook['id']}", headers=human())).text):
        assert secret not in response and "secret" not in response
    assert secret not in str([a async for a in db["audit_logs"].find({})])
    rotated = (await client.post(f"/api/v1/integrations/webhooks/{hook['id']}/rotate-secret", headers=human())).json()["secret"]
    assert rotated != secret and ev.decrypt_secret((await db["webhook_subscriptions"].find_one({"_id": hook["id"]}))["secret_enc"]) == rotated


@pytest.mark.asyncio
async def test_webhook_validation_roles_and_limits(client, db):
    post = lambda body, user=ADMIN: client.post("/api/v1/integrations/webhooks", json={"name": "SOAR", "events": ["*"], **body}, headers=human(user))
    for url in ("http://soar.example/hook", "https://localhost/x", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://u:p@soar.example", "soar.example"):
        assert (await post({"url": url})).status_code == 422, url
    assert (await post({"url": "https://soar.example/h", "events": ["nonsense"]})).status_code == 422
    assert (await post({"url": "https://soar.example/h"}, ANALYST)).status_code == 403
    assert (await client.get("/api/v1/integrations/webhooks")).status_code == 401
    for i in range(integrations_module.MAX_WEBHOOKS):
        assert (await post({"url": f"https://soar.example/{i}"})).status_code == 201
    assert (await post({"url": "https://soar.example/extra"})).status_code == 409


@pytest.mark.asyncio
async def test_patch_delete_and_isolation_between_tenants(client, db):
    hook = await new_hook(client, db)
    path = f"/api/v1/integrations/webhooks/{hook['id']}"
    assert (await client.get(path, headers=human(GLOBEX_ADMIN))).status_code == 404
    assert (await client.delete(path, headers=human(GLOBEX_ADMIN))).status_code == 404
    patched = (await client.patch(path, json={"name": "Renamed", "events": ["response.*"]}, headers=human())).json()
    assert patched["name"] == "Renamed" and patched["events"] == ["response.*"]
    assert (await client.patch(path, json={}, headers=human())).status_code == 422
    assert (await client.patch(path, json={"url": "http://insecure.example"}, headers=human())).status_code == 422
    await audit(db, "response.requested")
    assert await db["webhook_deliveries"].count_documents({"subscription_id": hook["id"]}) == 1
    assert (await client.delete(path, headers=human())).status_code == 200
    assert await db["webhook_deliveries"].count_documents({}) == 0 and await db["webhook_subscriptions"].count_documents({}) == 0


# ---------- delivery ----------

@pytest.mark.asyncio
async def test_matching_events_are_delivered_signed_and_others_are_not_queued(client, db, monkeypatch):
    receiver = Receiver(monkeypatch)
    hook = await new_hook(client, db, events=["alert.*"])
    other_tenant = await new_hook(client, db, events=["*"], user=GLOBEX_ADMIN)
    await audit(db, "alert.close", entity="a-7")
    await audit(db, "incident.merged", entity="i-1")
    await audit(db, "alert.close", org="globex", entity="g-9")
    assert await db["webhook_deliveries"].count_documents({"subscription_id": hook["id"]}) == 1
    assert await db["webhook_deliveries"].count_documents({"subscription_id": other_tenant["id"]}) == 1  # only Globex's own event

    assert await ev.deliver_due(db) == 2
    request = next(r for r in receiver.requests)
    sent = request.content.decode()
    timestamp = request.headers["x-forensiq-timestamp"]
    expected = "sha256=" + hmac.new(hook["secret"].encode(), f"{timestamp}.{sent}".encode(), hashlib.sha256).hexdigest()
    mine = next(r for r in receiver.requests if r.headers["x-forensiq-signature"] == expected)  # Globex's delivery was signed with Globex's secret
    body = json.loads(mine.content)
    assert mine.headers["x-forensiq-event"] == "alert.close" and mine.headers["content-type"] == "application/json"
    assert body["type"] == "alert.close" and body["tenant"] == "acme" and body["data"]["entity_id"] == "a-7" and body["seq"] == 2  # seq 1 was the hook's own creation event
    assert abs(int(mine.headers["x-forensiq-timestamp"]) - datetime.now(timezone.utc).timestamp()) < 30
    assert all(d["status"] == "delivered" for d in [x async for x in db["webhook_deliveries"].find({})])
    assert (await db["webhook_subscriptions"].find_one({"_id": hook["id"]}))["consecutive_failures"] == 0
    assert await ev.deliver_due(db) == 0  # nothing is sent twice


@pytest.mark.asyncio
async def test_failures_retry_with_backoff_then_go_dead(client, db, monkeypatch):
    Receiver(monkeypatch, status=500)
    hook = await new_hook(client, db)
    await audit(db)
    clock = datetime.now(timezone.utc)
    for attempt, wait in enumerate(ev.BACKOFF_SECONDS, start=1):
        assert await ev.deliver_due(db, clock) == 1
        delivery = await db["webhook_deliveries"].find_one({})
        assert delivery["status"] == "pending" and delivery["attempts"] == attempt and delivery["last_error"] == "HTTP 500"
        gap = (delivery["next_attempt_at"].replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds()
        assert wait - 5 <= gap <= wait + 5
        assert await ev.deliver_due(db, clock) == 0  # not due yet
        clock = delivery["next_attempt_at"].replace(tzinfo=timezone.utc) + timedelta(seconds=1)
    assert await ev.deliver_due(db, clock) == 1
    dead = await db["webhook_deliveries"].find_one({})
    assert dead["status"] == "dead" and dead["attempts"] == ev.MAX_ATTEMPTS
    assert await ev.deliver_due(db, clock + timedelta(days=1)) == 0
    assert (await db["webhook_subscriptions"].find_one({"_id": hook["id"]}))["consecutive_failures"] == ev.MAX_ATTEMPTS


@pytest.mark.asyncio
async def test_a_receiver_that_recovers_gets_the_event_and_a_dead_delivery_can_be_redelivered(client, db, monkeypatch):
    receiver = Receiver(monkeypatch, status=503)
    hook = await new_hook(client, db)
    await audit(db)
    await ev.deliver_due(db)
    assert (await db["webhook_deliveries"].find_one({}))["status"] == "pending"
    receiver.status = 200
    await db["webhook_deliveries"].update_one({}, {"$set": {"next_attempt_at": datetime.now(timezone.utc) - timedelta(seconds=1)}})
    await ev.deliver_due(db)
    delivery = await db["webhook_deliveries"].find_one({})
    assert delivery["status"] == "delivered" and delivery["attempts"] == 2
    assert (await db["webhook_subscriptions"].find_one({"_id": hook["id"]}))["consecutive_failures"] == 0

    await db["webhook_deliveries"].update_one({}, {"$set": {"status": "dead"}})
    path = f"/api/v1/integrations/webhooks/{hook['id']}/deliveries/{delivery['_id']}/redeliver"
    assert (await client.post(path, headers=human(GLOBEX_ADMIN))).status_code == 404
    assert (await client.post(path, headers=human())).status_code == 200
    await ev.deliver_due(db)
    business = [r for r in receiver.requests if not r.headers["x-forensiq-event"].startswith("integration.")]  # redelivering is itself an audited event
    assert len(business) == 3
    listing = (await client.get(f"/api/v1/integrations/webhooks/{hook['id']}/deliveries", headers=human())).json()
    assert listing[0]["status"] == "delivered" and "payload" not in listing[0]


@pytest.mark.asyncio
async def test_unsafe_targets_are_refused_at_delivery_time_even_if_saved_earlier(client, db, monkeypatch):
    monkeypatch.undo()  # use the real address check, not the test stub
    for url in ("https://127.0.0.1/hook", "https://169.254.169.254/latest", "https://[::1]/x", "http://soar.example/hook"):
        with pytest.raises(ValueError):
            await ev.assert_deliverable(url)
    await ev.assert_deliverable("https://203.0.113.5/hook")
    await ev.assert_deliverable("https://10.1.2.3/hook")  # private SOAR platforms are normal


@pytest.mark.asyncio
async def test_a_subscription_that_keeps_failing_is_disabled_and_audited(client, db, monkeypatch):
    Receiver(monkeypatch, status=500)
    hook = await new_hook(client, db)
    await db["webhook_subscriptions"].update_one({"_id": hook["id"]}, {"$set": {"consecutive_failures": ev.DISABLE_AFTER_CONSECUTIVE_FAILURES - 1}})
    await audit(db)
    await ev.deliver_due(db)
    stored = await db["webhook_subscriptions"].find_one({"_id": hook["id"]})
    assert stored["enabled"] is False and "consecutive failed" in stored["disabled_reason"]
    assert await db["audit_logs"].count_documents({"action": "integration.webhook_disabled", "org_id": "acme"}) == 1
    before = await db["webhook_deliveries"].count_documents({})
    await audit(db, "alert.escalate")
    assert await db["webhook_deliveries"].count_documents({}) == before  # disabled subscriptions queue nothing
    again = (await client.patch(f"/api/v1/integrations/webhooks/{hook['id']}", json={"enabled": True}, headers=human())).json()
    assert again["enabled"] and again["consecutive_failures"] == 0 and again["disabled_reason"] is None


@pytest.mark.asyncio
async def test_two_dispatchers_never_send_the_same_delivery_twice(client, db, monkeypatch):
    receiver = Receiver(monkeypatch)
    await new_hook(client, db)
    for i in range(5):
        await audit(db, entity=f"a-{i}")
    sent = await asyncio.gather(ev.deliver_due(db), ev.deliver_due(db), ev.deliver_due(db))
    assert sum(sent) == 5 and len(receiver.requests) == 5
    assert len({r.headers["x-forensiq-delivery"] for r in receiver.requests}) == 5


@pytest.mark.asyncio
async def test_a_stuck_claim_is_released_so_a_crashed_dispatcher_loses_nothing(client, db, monkeypatch):
    receiver = Receiver(monkeypatch)
    await new_hook(client, db)
    await audit(db)
    await db["webhook_deliveries"].update_one({}, {"$set": {"status": "sending", "claimed_at": datetime.now(timezone.utc) - timedelta(seconds=ev.CLAIM_TIMEOUT_SECONDS + 5)}})
    assert await ev.deliver_due(db) == 1 and len(receiver.requests) == 1


@pytest.mark.asyncio
async def test_the_test_button_reports_the_receivers_answer_and_does_not_queue_retries(client, db, monkeypatch):
    receiver = Receiver(monkeypatch, status=200)
    hook = await new_hook(client, db)
    ok = (await client.post(f"/api/v1/integrations/webhooks/{hook['id']}/test", headers=human())).json()
    assert ok == {"ok": True, "status_code": 200, "error": None}
    assert receiver.requests[0].headers["x-forensiq-event"] == "webhook.test"
    receiver.status = 401
    failed = (await client.post(f"/api/v1/integrations/webhooks/{hook['id']}/test", headers=human())).json()
    assert failed == {"ok": False, "status_code": 401, "error": "HTTP 401"}
    assert await ev.deliver_due(db) == 0  # the failed test is not retried in the background
    assert (await client.post(f"/api/v1/integrations/webhooks/{hook['id']}/test", headers=human(GLOBEX_ADMIN))).status_code == 404
