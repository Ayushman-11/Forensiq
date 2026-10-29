"""
Cross-tenant isolation, run automatically against EVERY mounted endpoint.

How it works
- Tenant A is seeded with a record in every tenant-owned collection, each carrying a canary string.
- The test walks `app.routes`. For each route and method it builds a request from the OpenAPI schema (path ids and
  body fields that name a resource are filled with tenant A's ids) and sends it as a user of tenant B, once per role.
- It then asserts, for that endpoint:
    1. no tenant A canary appears anywhere in the response,
    2. addressing one of A's resources by id never succeeds,
    3. none of A's stored documents changed and none were created,
    4. nothing returned a server error (a crash could hide a leak).
- A positive control sends the same requests as tenant A and requires real data back, so a harness that has
  silently stopped reaching handlers fails loudly instead of passing vacuously.

New endpoints are covered with no test changes. The suite fails (instead of skipping) when a route has a path
parameter or collection it does not know about, or an unauthenticated route nobody has reviewed: that is the prompt
to decide how it isolates tenants. Update the registries below deliberately.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.database.session import get_db
from app.main import app
from app.services.tenants import encrypt_secret

A, B = "tenant-a", "tenant-b"
CANARY = "CANARY-TENANT-A-7f3a91"
NOW = datetime.now(timezone.utc)
T0 = NOW - timedelta(hours=2)

# ---- registries (review when they fail) -------------------------------------------------------------------------

# Path parameter / body field name -> tenant A's id for that resource.
A_IDS = {
    "alert_id": "a-alert-1", "incident_id": "a-inc-1", "request_id": "a-resp-1", "ticket_id": "a-ticket-1",
    "job_id": "a-job-1", "user_id": "a-user-admin", "org_id": A, "channel_id": "a-chan-1", "owner_id": "a-user-admin",
    "note_id": "a-note-1", "webhook_id": "a-hook-1", "token_id": "a-token-1", "delivery_id": "a-delivery-1",
}
A_ID_VALUES = set(A_IDS.values()) | {"a-inc-2", "a-alert-2"}
# List-valued fields that hold ids of A's resources.
A_ID_LISTS = {"source_ids": ["a-inc-2"], "alert_ids": ["a-alert-1", "a-alert-2"]}

# Routes that require no login. Each must be justified; anything not listed here must require authentication.
PUBLIC_ROUTES = {
    ("GET", "/api/v1/health"): "platform liveness probe: reports the platform SIEM only, no tenant data",
    ("POST", "/api/v1/auth/login"): "login",
    ("POST", "/api/v1/auth/mfa/challenge"): "second login step, authenticated by the MFA token",
    ("POST", "/api/v1/auth/refresh"): "authenticated by the refresh token",
    ("POST", "/api/v1/auth/logout"): "authenticated by the refresh token",
    ("GET", "/api/v1/auth/sso/authorize"): "starts an SSO flow",
    ("POST", "/api/v1/auth/sso/callback"): "completes an SSO flow",
}

# WebSocket routes are authenticated by single-use tickets; their tenant checks are in test_investigation_websocket.py.
WEBSOCKET_ROUTES = {"/api/v1/alerts/{alert_id}/ws", "/api/v1/alerts/ws/{alert_id:path}"}

# Collections that are not tenant data (infrastructure, global caches, or keyed by something other than tenant).
GLOBAL_COLLECTIONS = {
    "ioc_cache": "public reputation lookups shared across tenants by design",
    "schema_versions": "schema migration marker",
    "rate_limits": "per-caller counters",
    "login_attempts": "per-email/IP throttle",
    "leases": "poller leases (per tenant name, no tenant content)",
    "ws_tickets": "single-use tickets bound to one user",
    "policies": None,  # tenant-owned, seeded below
}
TENANT_COLLECTIONS = {
    "alerts", "users", "incidents", "investigation_jobs", "tenants", "response_requests", "sessions", "notification_channels",
    "audit_logs", "ingestion_runs", "alert_notes", "investigation_events", "incident_notes", "incident_events", "llm_usage",
    "ingestion_state", "tenant_runtime", "policies", "webhook_subscriptions", "webhook_deliveries", "outbound_events", "api_tokens", "counters",
}

ROLES = ("admin", "soc_manager", "soc_analyst")
# Endpoints allowed to answer 5xx in this harness (none today). Do not add to hide a crash.
KNOWN_5XX: set[tuple[str, str]] = set()


def user(org: str, role: str) -> dict:
    prefix = "a" if org == A else "b"
    return {"id": f"{prefix}-user-{role.replace('soc_', '')}", "email": f"{role}@{org}.example", "role": role, "org_id": org, "is_active": True}


# ---- seed ------------------------------------------------------------------------------------------------------

def seed_documents() -> dict[str, list[dict]]:
    docs: dict[str, list[dict]] = {name: [] for name in TENANT_COLLECTIONS}

    def add(collection, **doc):
        docs[collection].append(doc)

    for org, prefix in ((A, "a"), (B, "b")):
        mark = CANARY if org == A else "benign-b"
        add("tenants", _id=org, name=f"{mark} Corp", status="active", created_at=T0, config={
            "siem": {"url": f"https://splunk.{prefix}.example", "username": f"{mark}-user", "password_enc": encrypt_secret(f"{mark}-pw"), "enabled": True},
            "threat_intel": {"vt_api_key_enc": encrypt_secret(f"{mark}-vt-key")},
            "noise": {"benign_domains": [f"{mark}.example"], "shared_hosting_domains": [], "suppress": []},
        })
        for role in ROLES:
            u = user(org, role)
            add("users", _id=u["id"], email=f"{mark}-{role}@{org}.example", role=role, org_id=org, is_active=True, password_hash="x", created_at=T0.isoformat())
        add("sessions", _id=f"{prefix}-sess-1", user_id=f"{prefix}-user-admin", user_agent=f"{mark} browser", expires_at=NOW + timedelta(days=1), created_at=T0)
        for i in (1, 2):
            add("alerts", _id=f"{prefix}-alert-{i}", org_id=org, title=f"{mark} suspicious powershell {i}", host=f"{mark}-host", user=f"{mark}-user",
                severity="high", status="New" if i == 1 else "Closed", rule_name=f"{mark}_rule", incident_id=f"{prefix}-inc-{i}",
                created_at=T0, detected_at=T0, first_seen=T0, extracted_iocs=[f"{mark}.evil.example"], source_ip="203.0.113.7",
                risk_assessment={"risk_score": 80, "reasoning": mark}, enrichments=[], recommendation=f"{mark} isolate", mitre_mappings=[],
                timeline=[], correlations=[], verdict="true_positive" if i == 2 else None, resolved_at=T0 if i == 2 else None)
            add("incidents", _id=f"{prefix}-inc-{i}", org_id=org, keys=[f"host:{mark}-host"], first_seen=T0, last_seen=T0, severity="high",
                alert_count=1, hosts=[f"{mark}-host"], users=[f"{mark}-user"], rules=[f"{mark}_rule"], status="open", created_at=T0,
                tickets=[{"id": f"{prefix}-ticket-{i}", "system": "jira", "key": f"SEC-{i}", "url": f"https://jira.{prefix}.example/browse/SEC-{i}",
                          "external_status": mark, "mapped_status": "open", "sync_state": "ok", "sync_error": None, "linked_by": f"{mark}@x",
                          "linked_at": T0, "last_synced_at": T0, "sys_id": None}] if i == 1 else [])
        add("alert_notes", _id=f"{prefix}-note-1", org_id=org, alert_id=f"{prefix}-alert-1", content=f"{mark} analyst note", author_email=f"{mark}@x", created_at=T0)
        add("incident_notes", _id=f"{prefix}-inote-1", org_id=org, incident_id=f"{prefix}-inc-1", content=f"{mark} case note", author_email=f"{mark}@x", created_at=T0)
        add("incident_events", _id=f"{prefix}-ievent-1", org_id=org, incident_id=f"{prefix}-inc-1", type="note_added", actor_email=f"{mark}@x", at=T0, data={"preview": mark})
        add("audit_logs", _id=f"{prefix}-audit-1", org_id=org, actor_id=f"{prefix}-user-admin", actor_email=f"{mark}@x", action="alert.close",
            entity_type="alert", entity_id=f"{prefix}-alert-1", metadata={"note": mark}, created_at=T0)
        add("response_requests", _id=f"{prefix}-resp-1", org_id=org, action_type="edr.isolate_host", target=f"{mark}-host", reason=f"{mark} confirmed C2 beaconing",
            alert_id=f"{prefix}-alert-1", incident_id=f"{prefix}-inc-1", status="pending_approval", requested_by={"id": f"{prefix}-user-analyst", "email": f"{mark}@x"},
            requested_at=NOW, updated_at=NOW, preview={"status": "ok", "summary": mark}, executions=[])
        add("investigation_jobs", _id=f"{prefix}-job-1", alert_id=f"{prefix}-alert-1", org_id=org, status="succeeded", error_note=mark, priority="normal", created_at=T0,
            started_at=T0, completed_at=T0, worker_id=None, lease_expires_at=None, retries=0, max_retries=3, error=None, error_ref=None)
        add("investigation_events", _id=f"{prefix}-ievt-1", alert_id=f"{prefix}-alert-1", org_id=org, event="step", data={"message": mark}, created_at=T0)
        add("notification_channels", _id=f"{prefix}-chan-1", org_id=org, name=f"{mark} slack", channel_type="slack", enabled=True, webhook_url=f"https://hooks.example/{mark}")
        add("policies", _id=f"{prefix}-pol-1", org_id=org, policy_type="sla_targets", version=1, is_active=True,
            content={"critical": [5, 60]}, reason=mark, created_by=f"{mark}@x", created_at=T0)
        add("ingestion_runs", _id=f"{prefix}-run-1", org_id=org, started_at=T0, finished_at=T0, status="ok", fetched=1, alerts_new=1, suppressed={}, errors=[], lag_seconds=1, stage=mark)
        add("ingestion_state", _id=f"cursor:{org}:splunk", ts=T0.isoformat(), truncated=False, fetched=0, note=mark)
        add("tenant_runtime", _id=org, last_poll_at=T0, last_error=mark if org == A else None, consecutive_failures=0)
        add("webhook_subscriptions", _id=f"{prefix}-hook-1", org_id=org, name=f"{mark} SOAR", url=f"https://hooks.{prefix}.example/{mark}", events=["*"], enabled=True,
            secret_enc=encrypt_secret(f"whsec_{mark}"), created_by=f"{mark}@x", created_at=T0, consecutive_failures=0)
        add("webhook_deliveries", _id=f"{prefix}-delivery-1", org_id=org, subscription_id=f"{prefix}-hook-1", event_id=f"{prefix}-event-1", event_type="alert.close",
            status="dead", attempts=6, next_attempt_at=T0, created_at=T0, last_error=f"{mark} refused", last_status_code=500)
        add("outbound_events", _id=f"{prefix}-event-1", org_id=org, seq=1, type="alert.close", created_at=T0, actor=f"{mark}@x", data={"entity_id": f"{prefix}-alert-1", "note": mark})
        add("api_tokens", _id=f"{prefix}-token-1", org_id=org, name=f"{mark} pipeline", token_hash=f"hash-{prefix}", prefix=f"fsq_{prefix}000", scopes=["alerts:read"],
            created_by=f"{mark}@x", created_at=T0, expires_at=NOW + timedelta(days=30), last_used_at=None, revoked_at=None)
        add("counters", _id=f"events:{org}", seq=1, note=mark)
        add("llm_usage", _id=f"{prefix}-llm-1", org_id=org, day=T0.date().isoformat(), tokens=10, note=mark)
    return docs


@pytest.fixture
async def world(monkeypatch):
    db = AsyncMongoMockClient()[f"isolation_{id(object())}"]
    seeded = seed_documents()
    snapshot_ids: dict[str, list[str]] = {}
    for collection, docs in seeded.items():
        if docs:
            await db[collection].insert_many([dict(d) for d in docs])
        snapshot_ids[collection] = [d["_id"] for d in docs if _owned_by_a(collection, d)]

    holder = {"user": user(B, "admin")}

    async def _db():
        return db

    async def _user():
        return dict(holder["user"])

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user

    # No real outbound traffic: connectors, SIEM, LLM and ticketing all fail like an unreachable network.
    async def no_network(self, request):
        raise httpx.ConnectError("network disabled in tests")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", no_network)
    try:
        yield db, holder, snapshot_ids
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


def _owned_by_a(collection: str, doc: dict) -> bool:
    if collection == "tenants" or collection == "tenant_runtime":
        return doc["_id"] == A
    if collection == "users":
        return doc["org_id"] == A
    if collection == "sessions":
        return doc["user_id"].startswith("a-")
    if collection == "ingestion_state":
        return f":{A}:" in doc["_id"]
    if collection == "counters":
        return doc["_id"].endswith(A)
    return doc.get("org_id") == A


async def a_state(db, snapshot_ids) -> dict:
    """Everything tenant A owns, as comparable text, plus how many documents claim to be A's."""
    state = {}
    for collection, ids in snapshot_ids.items():
        docs = [await db[collection].find_one({"_id": i}) for i in ids]
        state[collection] = json.dumps(docs, default=str, sort_keys=True)
        state[f"{collection}#count"] = await db[collection].count_documents({"org_id": A}) if collection not in ("tenants", "tenant_runtime", "sessions", "ingestion_state", "counters") else len(docs)
    return state


# ---- request generation ----------------------------------------------------------------------------------------

OPENAPI = None


def openapi() -> dict:
    global OPENAPI
    if OPENAPI is None:
        OPENAPI = app.openapi()
    return OPENAPI


def resolve(schema: dict) -> dict:
    while "$ref" in schema:
        node = openapi()
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node[part]
        schema = node
    return schema


def sample(schema: dict, name: str = "") -> object:
    schema = resolve(schema)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [o for o in schema[key] if resolve(o).get("type") != "null"]
            return sample(options[0], name) if options else None
    if "allOf" in schema:
        return sample(schema["allOf"][0], name)
    if name in A_IDS:
        return A_IDS[name]
    if name in A_ID_LISTS:
        return A_ID_LISTS[name]
    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        out = {}
        for prop, sub in props.items():
            if prop in required or prop in A_IDS or prop in A_ID_LISTS:
                out[prop] = sample(sub, prop)
        return out
    if kind == "array":
        item = sample(schema.get("items", {}), name)
        return [item] if schema.get("minItems", 0) > 0 or name.endswith("s") else []
    if kind == "integer":
        return max(int(schema.get("minimum", 1)), 1)
    if kind == "number":
        return float(schema.get("minimum", 1))
    if kind == "boolean":
        return False
    if kind == "string":
        if schema.get("format") == "email":
            return "someone@example.com"
        if schema.get("format") in ("date-time", "date"):
            return NOW.isoformat()
        return "x" * max(schema.get("minLength", 1), 12)
    return None


class Route:
    """One concrete route. FastAPI resolves nested routers lazily, so flatten them through the effective contexts."""

    def __init__(self, path: str, methods, dependant, websocket: bool):
        self.path, self.methods, self.dependant, self.websocket = path, set(methods or ()), dependant, websocket


def flat_routes() -> list[Route]:
    out = []

    def add(ctx):
        original = ctx.original_route
        is_ws = isinstance(original, APIWebSocketRoute)
        out.append(Route(ctx.path, getattr(ctx, "methods", None), getattr(ctx, "dependant", None), is_ws))

    for route in app.routes:
        if hasattr(route, "effective_route_contexts"):
            for ctx in route.effective_route_contexts():
                add(ctx)
        elif isinstance(route, (APIRoute, APIWebSocketRoute)):
            out.append(Route(route.path, getattr(route, "methods", None), route.dependant, isinstance(route, APIWebSocketRoute)))
    return [r for r in out if r.path.startswith("/api/v1")]


def build_request(route: Route, method: str) -> tuple[str, dict | None, dict]:
    op = openapi()["paths"].get(route.path, {}).get(method.lower(), {})
    path = route.path
    for param in op.get("parameters", []):
        if param["in"] == "path":
            if param["name"] not in A_IDS:
                pytest.fail(f"{method} {route.path}: path parameter {param['name']!r} has no tenant A id in A_IDS; add the fixture and seed data for it")
            path = path.replace("{" + param["name"] + "}", A_IDS[param["name"]])
    params = {p["name"]: sample(p["schema"], p["name"]) for p in op.get("parameters", []) if p["in"] == "query" and p.get("required")}
    body = None
    content = (op.get("requestBody") or {}).get("content", {})
    if "application/json" in content:
        body = sample(content["application/json"]["schema"])
    return path, body, params


def all_routes() -> list[tuple[str, Route]]:
    return [(method, route) for route in flat_routes() if not route.websocket for method in sorted(route.methods - {"HEAD", "OPTIONS"})]


def requires_auth(route: Route) -> bool:
    def walk(dependant) -> bool:
        return any(d.call is get_current_user or walk(d) for d in dependant.dependencies)

    return walk(route.dependant)


ROUTES = all_routes()
ROUTE_IDS = [f"{m} {r.path}" for m, r in ROUTES]


async def send(client: AsyncClient, method: str, path: str, body, params):
    return await client.request(method, path, json=body, params=params)


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


# ---- the suite -------------------------------------------------------------------------------------------------

def test_every_route_is_either_authenticated_or_explicitly_public():
    open_routes = {(m, r.path) for m, r in ROUTES if not requires_auth(r)}
    assert open_routes == set(PUBLIC_ROUTES), (
        f"unreviewed unauthenticated routes: {sorted(open_routes - set(PUBLIC_ROUTES))}; "
        f"stale PUBLIC_ROUTES entries: {sorted(set(PUBLIC_ROUTES) - open_routes)}"
    )


def test_websocket_routes_are_known():
    def walk(router, prefix=""):
        for r in router.routes:
            if hasattr(r, "original_router"):
                yield from walk(r.original_router, prefix + (getattr(r.include_context, "prefix", "") or ""))
            elif isinstance(r, APIWebSocketRoute):
                yield prefix + r.path

    found = {p for p in walk(app.router) if p.startswith("/api/v1")}
    assert found == WEBSOCKET_ROUTES, f"new/removed WebSocket routes: {sorted(found ^ WEBSOCKET_ROUTES)}; review their tenant checks"


def test_every_collection_the_app_uses_has_an_isolation_decision():
    names = set()
    for path in Path(__file__).resolve().parents[1].joinpath("app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        names |= set(re.findall(r'\bdb\["([a-z_]+)"\]', text))
        names |= set(re.findall(r'[A-Z_]*COLLECTION\s*=\s*"([a-z_]+)"', text))
    undecided = names - TENANT_COLLECTIONS - set(GLOBAL_COLLECTIONS)
    assert not undecided, f"collections with no isolation decision: {sorted(undecided)}. Seed them in seed_documents() or justify in GLOBAL_COLLECTIONS"


@pytest.mark.asyncio
async def test_seeded_tenant_data_is_really_tenant_a_s(world):
    db, _, snapshot_ids = world
    assert all(snapshot_ids[c] for c in TENANT_COLLECTIONS - {"policies"} | {"policies"}), "every tenant-owned collection needs a tenant A record"
    for collection in TENANT_COLLECTIONS:
        text = json.dumps([d async for d in db[collection].find({})], default=str)
        assert CANARY in text, f"{collection} has no canary: tenant A data would not be detectable there"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,route", ROUTES, ids=ROUTE_IDS)
async def test_tenant_b_cannot_read_or_change_tenant_a_through_this_endpoint(method, route, world, client):
    if (method, route.path) in PUBLIC_ROUTES:
        pytest.skip(f"public route: {PUBLIC_ROUTES[(method, route.path)]}")
    db, holder, snapshot_ids = world
    path, body, params = build_request(route, method)
    addresses_a = any(a_id in path for a_id in A_ID_VALUES)
    before = await a_state(db, snapshot_ids)

    for role in ROLES:
        holder["user"] = user(B, role)
        resp = await send(client, method, path, body, params)
        where = f"{method} {path} as tenant B {role}"
        assert CANARY not in resp.text, f"LEAK: {where} returned tenant A data: {resp.text[:300]}"
        if addresses_a:
            assert not (200 <= resp.status_code < 300), f"{where} succeeded against tenant A's resource ({resp.status_code}): {resp.text[:200]}"
        # 502/503/504 are honest "upstream unreachable" answers (the network is disabled here); 500 is a crash.
        if resp.status_code == 500 or resp.status_code > 504:
            assert (method, route.path) in KNOWN_5XX, f"{where} crashed ({resp.status_code}): {resp.text[:200]}"
        assert await a_state(db, snapshot_ids) == before, f"{where} changed tenant A's data"


@pytest.mark.asyncio
async def test_positive_control_tenant_a_reaches_its_own_data_through_the_same_requests(world, client):
    """If this fails, the isolation checks above may be passing only because requests never reach a handler."""
    db, holder, _ = world
    holder["user"] = user(A, "admin")
    served = []
    for method, route in ROUTES:
        if method != "GET" or (method, route.path) in PUBLIC_ROUTES or "stream" in route.path:
            continue
        path, body, params = build_request(route, method)
        resp = await send(client, method, path, body, params)
        if resp.status_code == 200 and CANARY in resp.text:
            served.append(route.path)
    expected_some = {"/api/v1/alerts/{alert_id}", "/api/v1/incidents/{incident_id}", "/api/v1/response/{request_id}", "/api/v1/tenants/current/settings", "/api/v1/admin/users",
                     "/api/v1/integrations/webhooks/{webhook_id}", "/api/v1/integrations/webhooks", "/api/v1/integrations/tokens", "/api/v1/events"}
    assert expected_some <= set(served), f"tenant A could not read its own data at: {sorted(expected_some - set(served))}"
    assert len(served) >= 10, f"only {len(served)} endpoints served tenant A's canary: {sorted(served)}"


@pytest.mark.asyncio
async def test_a_tenant_admin_cannot_use_platform_administration(world, client):
    db, holder, snapshot_ids = world
    holder["user"] = user(B, "admin")
    before = await a_state(db, snapshot_ids)
    assert (await client.get("/api/v1/tenants")).status_code == 403
    assert (await client.post("/api/v1/tenants", json={"id": "evil", "name": "Evil", "admin_email": "e@evil.example", "admin_password": "x" * 14})).status_code == 403
    assert (await client.get(f"/api/v1/tenants/{A}/settings")).status_code == 403
    assert (await client.put(f"/api/v1/tenants/{A}/settings", json={"reason": "take over", "siem": {"url": "https://evil.example"}})).status_code == 403
    assert (await client.patch(f"/api/v1/tenants/{A}", json={"status": "suspended"})).status_code == 403
    assert await a_state(db, snapshot_ids) == before
