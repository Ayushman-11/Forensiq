"""
Production-readiness 2.7: API tokens for service accounts with scoped permissions.

These tests use the real authentication dependency (unlike the isolation suite, which replaces it).
"""

import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.core.security import create_access_token
from app.database.session import get_db
from app.main import app
from app.services import api_tokens
from tests.test_tenant_isolation import ROUTES, build_request

NOW = datetime.now(timezone.utc)
ACME_ADMIN = {"id": "u-admin", "email": "admin@acme.example", "role": "admin", "org_id": "acme"}

# The reviewed list of every route a token can reach, and the one scope that opens it. Changing it is a security decision.
TOKEN_REACHABLE = {
    ("GET", "/api/v1/alerts/", "alerts:read"), ("GET", "/api/v1/alerts/investigation/{job_id}", "alerts:read"),
    ("GET", "/api/v1/alerts/stats/by-rule", "alerts:read"), ("GET", "/api/v1/alerts/stats/mitre", "alerts:read"),
    ("GET", "/api/v1/alerts/stats/timeline", "alerts:read"), ("GET", "/api/v1/alerts/{alert_id:path}/audit", "alerts:read"),
    ("GET", "/api/v1/alerts/{alert_id:path}/investigations", "alerts:read"), ("GET", "/api/v1/alerts/{alert_id:path}/notes", "alerts:read"),
    ("GET", "/api/v1/alerts/{alert_id:path}/report", "alerts:read"), ("GET", "/api/v1/alerts/{alert_id:path}/report/executive", "alerts:read"),
    ("GET", "/api/v1/alerts/{alert_id:path}/report/full", "alerts:read"), ("GET", "/api/v1/alerts/{alert_id:path}/report/pdf", "alerts:read"),
    ("GET", "/api/v1/alerts/{alert_id}", "alerts:read"), ("GET", "/api/v1/dashboard/ingestion-health", "alerts:read"),
    ("GET", "/api/v1/dashboard/metrics", "alerts:read"), ("GET", "/api/v1/dashboard/soc-metrics", "alerts:read"),
    ("GET", "/api/v1/dashboard/system-health", "alerts:read"),
    ("PATCH", "/api/v1/alerts/{alert_id:path}/assignee", "alerts:write"), ("PATCH", "/api/v1/alerts/{alert_id:path}/disposition", "alerts:write"),
    ("POST", "/api/v1/alerts/bulk", "alerts:write"), ("POST", "/api/v1/alerts/{alert_id:path}/investigate", "alerts:write"),
    ("POST", "/api/v1/alerts/{alert_id:path}/notes", "alerts:write"),
    ("GET", "/api/v1/events", "events:read"), ("GET", "/api/v1/events/", "events:read"),
    ("GET", "/api/v1/incidents", "incidents:read"), ("GET", "/api/v1/incidents/{incident_id}", "incidents:read"),
    ("GET", "/api/v1/incidents/{incident_id}/notes", "incidents:read"), ("GET", "/api/v1/incidents/{incident_id}/timeline", "incidents:read"),
    ("DELETE", "/api/v1/incidents/{incident_id}/pin/{alert_id}", "incidents:write"), ("DELETE", "/api/v1/incidents/{incident_id}/tickets/{ticket_id}", "incidents:write"),
    ("POST", "/api/v1/incidents/{incident_id}/merge", "incidents:write"), ("POST", "/api/v1/incidents/{incident_id}/notes", "incidents:write"),
    ("POST", "/api/v1/incidents/{incident_id}/owner", "incidents:write"), ("POST", "/api/v1/incidents/{incident_id}/pin", "incidents:write"),
    ("POST", "/api/v1/incidents/{incident_id}/split", "incidents:write"), ("POST", "/api/v1/incidents/{incident_id}/status", "incidents:write"),
    ("POST", "/api/v1/incidents/{incident_id}/tickets", "incidents:write"), ("POST", "/api/v1/incidents/{incident_id}/tickets/{ticket_id}/sync", "incidents:write"),
    ("GET", "/api/v1/policies/escalation", "policies:read"), ("GET", "/api/v1/policies/sla", "policies:read"),
    ("GET", "/api/v1/response", "response:read"), ("GET", "/api/v1/response/capabilities", "response:read"), ("GET", "/api/v1/response/{request_id}", "response:read"),
    ("POST", "/api/v1/response", "response:request"), ("POST", "/api/v1/response/{request_id}/dry-run", "response:request"),
    ("POST", "/api/v1/search", "search:execute"), ("POST", "/api/v1/search/", "search:execute"),
}
# Things a token must never do, whatever scopes it holds.
NEVER_FOR_TOKENS = [
    ("POST", "/api/v1/response/x/approve"), ("POST", "/api/v1/response/x/reject"), ("POST", "/api/v1/response/x/execute"), ("POST", "/api/v1/response/x/rollback"),
    ("POST", "/api/v1/response/x/cancel"), ("POST", "/api/v1/alerts/ingest"), ("POST", "/api/v1/incidents/rebuild"), ("GET", "/api/v1/admin/users"),
    ("POST", "/api/v1/admin/users"), ("GET", "/api/v1/tenants"), ("PUT", "/api/v1/tenants/current/settings"), ("POST", "/api/v1/tenants"),
    ("GET", "/api/v1/integrations/tokens"), ("POST", "/api/v1/integrations/tokens"), ("GET", "/api/v1/integrations/webhooks"), ("POST", "/api/v1/auth/ws-ticket"),
    ("PUT", "/api/v1/policies/sla"), ("PUT", "/api/v1/policies/escalation"), ("GET", "/api/v1/dashboard/config"), ("GET", "/api/v1/users"),
]


@pytest.fixture
async def db():
    database = AsyncMongoMockClient()["tokens"]
    await database["alerts"].insert_many([
        {"_id": "a-1", "org_id": "acme", "title": "acme alert", "severity": "high", "status": "New", "host": "h1", "created_at": NOW, "detected_at": NOW},
        {"_id": "b-1", "org_id": "globex", "title": "globex alert", "severity": "high", "status": "New", "host": "h2", "created_at": NOW, "detected_at": NOW},
    ])
    await database["users"].insert_one({"_id": "u-admin", "email": "admin@acme.example", "role": "admin", "org_id": "acme", "is_active": True})

    async def _db():
        return database

    app.dependency_overrides[get_db] = _db
    yield database
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
async def client(db):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


def human(user=ACME_ADMIN):
    token = create_access_token(user_id=user["id"], email=user["email"], role=user["role"], org_id=user["org_id"])
    return {"Authorization": f"Bearer {token}"}


async def make_token(db, scopes, org="acme", name="ci-pipeline", days=30, **overrides):
    token, doc = await api_tokens.create_token(db, {"email": "admin@x", "org_id": org}, name, scopes, days)
    if overrides:
        await db["api_tokens"].update_one({"_id": doc["_id"]}, {"$set": overrides})
    return token, doc


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- management ----------

@pytest.mark.asyncio
async def test_a_token_is_shown_once_stored_only_as_a_hash_and_listed_without_its_secret(client, db):
    r = await client.post("/api/v1/integrations/tokens", json={"name": "SOAR pipeline", "scopes": ["alerts:read", "events:read"], "expires_in_days": 30}, headers=human())
    assert r.status_code == 201, r.text
    body = r.json()
    token = body["token"]
    assert token.startswith("fsq_") and len(token) > 40 and body["status"] == "active" and body["scopes"] == ["alerts:read", "events:read"]
    stored = await db["api_tokens"].find_one({"_id": body["id"]})
    assert stored["token_hash"] == api_tokens.hash_token(token) and token not in str(stored) and stored["org_id"] == "acme"
    listing = (await client.get("/api/v1/integrations/tokens", headers=human())).json()
    assert [t["name"] for t in listing] == ["SOAR pipeline"] and token not in str(listing) and listing[0]["prefix"] == token[:12]
    assert (await db["audit_logs"].find_one({"action": "integration.token_created"}))["metadata"]["scopes"] == ["alerts:read", "events:read"]
    assert token not in str(await db["audit_logs"].find_one({"action": "integration.token_created"}))


@pytest.mark.asyncio
async def test_token_creation_rules(client, db):
    create = lambda body, headers=None: client.post("/api/v1/integrations/tokens", json=body, headers=headers or human())
    assert (await create({"name": "x", "scopes": ["alerts:read"]})).status_code == 422
    assert (await create({"name": "ok-name", "scopes": []})).status_code == 422
    assert (await create({"name": "ok-name", "scopes": ["alerts:delete"]})).status_code == 422
    assert (await create({"name": "ok-name", "scopes": ["alerts:read"], "expires_in_days": 400})).status_code == 422
    assert (await create({"name": "ok-name", "scopes": ["alerts:read"], "expires_in_days": 0})).status_code == 422
    default = (await create({"name": "default-expiry", "scopes": ["alerts:read"]})).json()
    assert 89 <= (datetime.fromisoformat(default["expires_at"]) - datetime.now(timezone.utc)).days <= 90  # tokens always expire
    analyst = {"id": "u-an", "email": "l1@acme.example", "role": "soc_analyst", "org_id": "acme"}
    await db["users"].insert_one({"_id": "u-an", "email": analyst["email"], "role": "soc_analyst", "org_id": "acme", "is_active": True})
    assert (await create({"name": "ok-name", "scopes": ["alerts:read"]}, human(analyst))).status_code == 403
    for i in range(api_tokens.MAX_ACTIVE_TOKENS - 1):
        await make_token(db, ["alerts:read"], name=f"bulk-{i}")
    assert (await create({"name": "one-too-many", "scopes": ["alerts:read"]})).status_code == 409


@pytest.mark.asyncio
async def test_revoking_a_token_ends_access_immediately_and_only_for_the_owning_tenant(client, db):
    token, doc = await make_token(db, ["alerts:read"])
    assert (await client.get("/api/v1/alerts/", headers=bearer(token))).status_code == 200
    other_org_admin = {"id": "u-g", "email": "admin@globex.example", "role": "admin", "org_id": "globex"}
    await db["users"].insert_one({"_id": "u-g", "email": other_org_admin["email"], "role": "admin", "org_id": "globex", "is_active": True})
    assert (await client.delete(f"/api/v1/integrations/tokens/{doc['_id']}", headers=human(other_org_admin))).status_code == 404
    assert (await client.get("/api/v1/alerts/", headers=bearer(token))).status_code == 200
    assert (await client.delete(f"/api/v1/integrations/tokens/{doc['_id']}", headers=human())).status_code == 200
    assert (await client.get("/api/v1/alerts/", headers=bearer(token))).status_code == 401
    assert (await client.delete(f"/api/v1/integrations/tokens/{doc['_id']}", headers=human())).status_code == 404  # already revoked


# ---------- authentication ----------

@pytest.mark.asyncio
async def test_a_valid_token_reads_only_its_own_tenant_and_records_use(client, db):
    token, doc = await make_token(db, ["alerts:read"])
    r = await client.get("/api/v1/alerts/", headers=bearer(token))
    assert r.status_code == 200 and [a["_id"] for a in r.json()] == ["a-1"]  # globex's alert is not visible
    assert (await db["api_tokens"].find_one({"_id": doc["_id"]}))["last_used_at"] is not None
    globex_token, _ = await make_token(db, ["alerts:read"], org="globex", name="globex-reader")
    assert [a["_id"] for a in (await client.get("/api/v1/alerts/", headers=bearer(globex_token))).json()] == ["b-1"]
    assert (await client.get("/api/v1/alerts/b-1", headers=bearer(token))).status_code == 404


@pytest.mark.asyncio
async def test_invalid_expired_and_malformed_tokens_are_401(client, db):
    token, doc = await make_token(db, ["alerts:read"])
    for bad in (token + "x", "fsq_nonsense", "fsq_", "notatoken", token.replace("fsq_", "fsb_")):
        assert (await client.get("/api/v1/alerts/", headers=bearer(bad))).status_code == 401, bad
    await db["api_tokens"].update_one({"_id": doc["_id"]}, {"$set": {"expires_at": NOW - timedelta(seconds=1)}})
    r = await client.get("/api/v1/alerts/", headers=bearer(token))
    assert r.status_code == 401 and "expired" in r.json()["detail"]
    assert (await client.get("/api/v1/alerts/")).status_code == 401


@pytest.mark.asyncio
async def test_a_suspended_tenants_tokens_stop_working(client, db):
    token, _ = await make_token(db, ["alerts:read"])
    await db["tenants"].insert_one({"_id": "acme", "name": "Acme", "status": "suspended", "config": {}})
    r = await client.get("/api/v1/alerts/", headers=bearer(token))
    assert r.status_code == 403 and "suspended" in r.json()["detail"]


# ---------- authorisation ----------

@pytest.mark.asyncio
async def test_a_token_needs_the_scope_for_the_route_and_gets_nothing_else(client, db):
    reader, _ = await make_token(db, ["alerts:read"], name="reader")
    r = await client.post("/api/v1/search", json={"query": "index=main"}, headers=bearer(reader))
    assert r.status_code == 403 and "search:execute" in r.json()["detail"]
    r = await client.patch("/api/v1/alerts/a-1/disposition", json={"action": "close", "note": "x", "verdict": "true_positive"}, headers=bearer(reader))
    assert r.status_code == 403 and "alerts:write" in r.json()["detail"]
    assert (await db["alerts"].find_one({"_id": "a-1"}))["status"] == "New"


@pytest.mark.asyncio
async def test_a_token_with_a_write_scope_acts_as_a_service_account_in_the_audit_trail(client, db):
    token, doc = await make_token(db, ["alerts:write", "alerts:read"], name="soar")
    r = await client.post("/api/v1/alerts/a-1/notes", json={"content": "enriched by SOAR playbook 7"}, headers=bearer(token))
    assert r.status_code in (200, 201), r.text
    audit = await db["audit_logs"].find_one({"action": "alert.note_added"})
    assert audit["actor_email"] == "soar@service.acme" and audit["actor_id"] == f"svc:{doc['_id']}"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", NEVER_FOR_TOKENS)
async def test_a_token_with_every_scope_still_cannot_do_this(client, db, method, path):
    token, _ = await make_token(db, list(api_tokens.SCOPES))
    r = await client.request(method, path, headers=bearer(token), json={} if method in ("POST", "PUT", "PATCH") else None)
    assert r.status_code == 403 and "not available to API tokens" in r.json()["detail"], (method, path, r.status_code)


def test_the_set_of_routes_a_token_can_reach_is_exactly_the_reviewed_list():
    reachable = set()
    for method, route in ROUTES:
        scope = api_tokens.required_scope(method, re.sub(r"\{[^}]+\}", "x", route.path))
        if scope:
            reachable.add((method, route.path, scope))
    assert reachable == TOKEN_REACHABLE, (
        f"token-reachable routes changed. New: {sorted(reachable - TOKEN_REACHABLE)}; gone: {sorted(TOKEN_REACHABLE - reachable)}. "
        "Review each one: a token must never approve, execute, ingest or administer anything."
    )
    assert all(scope in api_tokens.SCOPES for _, _, scope in TOKEN_REACHABLE)
    assert {scope for _, _, scope in TOKEN_REACHABLE} == set(api_tokens.SCOPES), "every scope must open at least one route"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,template,scope", sorted(TOKEN_REACHABLE), ids=[f"{m} {p}" for m, p, _ in sorted(TOKEN_REACHABLE)])
async def test_every_reachable_route_opens_with_its_scope_and_not_without_it(client, db, method, template, scope):
    route = next(r for m, r in ROUTES if m == method and r.path == template)
    path, body, params = build_request(route, method)
    path = path.replace("a-alert-1", "a-1")  # the isolation fixtures use other ids; any id is fine here
    other_scopes = [s for s in api_tokens.SCOPES if s != scope]
    without, _ = await make_token(db, other_scopes, name="without")
    r = await client.request(method, path, json=body, params=params, headers=bearer(without))
    assert r.status_code == 403 and scope in r.json()["detail"]
    with_scope, _ = await make_token(db, [scope], name="with")
    r = await client.request(method, path, json=body, params=params, headers=bearer(with_scope))
    assert r.status_code not in (401,) and not (r.status_code == 403 and "scope" in str(r.json().get("detail", ""))), (r.status_code, r.text[:200])
