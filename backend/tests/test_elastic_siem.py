"""
Production-readiness 2.7: Elastic as a second SIEM behind the same provider interface.
"""

import json

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import search as search_module
from app.api.v1.endpoints import tenants as tenants_module
from app.database.session import get_db
from app.infrastructure.siem.elastic import ElasticClient, hit_to_event, hit_to_row, to_es_time
from app.normalization.clean import parse_ts
from app.normalization.mappers import to_canonical
from app.services import tenants as svc
from app.services.ingestion import EVENT_CODES, IngestionService

ADMIN = {"id": "u1", "email": "admin@elastic.example", "role": "admin", "org_id": "elk"}
PLATFORM = {"id": "p1", "email": "root@platform.example", "role": "admin", "org_id": "default"}

SYSMON_PROCESS = {
    "_index": ".ds-winlogbeat-8.14-2026.10.28", "_id": "abc123",
    "_source": {
        "@timestamp": "2026-10-28T10:15:30.123Z",
        "host": {"name": "WS-042"},
        "winlog": {
            "event_id": "1", "computer_name": "WS-042.corp.local", "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_data": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -enc SQBFAFgA",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "CORP\\alice",
                "Hashes": "SHA256=" + "a" * 64, "ProcessId": "4242", "UtcTime": "2026-10-28 10:15:30.123",
            },
        },
    },
    "sort": [1788000930123, 7],
}


def client_with(handler, **kw):
    client = ElasticClient(url="https://es.corp.example:9200", **kw)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers={"Authorization": f"ApiKey {kw.get('api_key')}"} if kw.get("api_key") else None)
    return client


# ---------- mapping ----------

def test_ecs_documents_become_rows_the_existing_normalisation_understands():
    row = hit_to_row(SYSMON_PROCESS)
    assert row["EventCode"] == "1" and row["host"] == "WS-042" and row["_time"] == "2026-10-28T10:15:30.123Z"
    assert row["_cd"] == ".ds-winlogbeat-8.14-2026.10.28:abc123"
    event = to_canonical(row)
    assert event is not None and event.event_code == "1"
    assert "powershell" in (event.fields.get("Image") or "").lower() and "-enc" in event.fields.get("CommandLine", "")
    assert event.ts == parse_ts("2026-10-28T10:15:30.123Z")
    assert to_canonical(row).event_id == event.event_id  # stable across cycles, so alerts dedupe


def test_ecs_fallbacks_fill_fields_winlogbeat_only_puts_under_process_and_user():
    hit = {"_index": "i", "_id": "x", "_source": {"@timestamp": "2026-10-28T10:00:00Z", "event": {"code": "3"}, "host": {"name": "h1"},
                                                  "process": {"executable": "C:\\a.exe", "pid": 7}, "user": {"name": "bob", "domain": "CORP"},
                                                  "destination": {"ip": "203.0.113.9", "port": 443}}}
    row = hit_to_row(hit)
    assert row["EventCode"] == "3" and row["Image"] == "C:\\a.exe" and row["User"] == "CORP\\bob" and row["DestinationIp"] == "203.0.113.9"
    event = hit_to_event(hit)
    assert event.hostname == "h1" and event.destination_port == 443 and event.process_name == "C:\\a.exe" and event.provider == "elastic"


@pytest.mark.parametrize("given,expected", [("-24h", "now-24h"), ("-7d", "now-7d"), ("now", "now"), ("1788000000", "1788000000"), ("", "now")])
def test_splunk_style_relative_times_become_date_math(given, expected):
    assert to_es_time(given) == expected


# ---------- client ----------

@pytest.mark.asyncio
async def test_authenticate_accepts_a_valid_key_and_reports_a_rejected_one():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"cluster_name": "prod"}) if seen["auth"] == "ApiKey good" else httpx.Response(401)

    assert await client_with(handler, api_key="good").authenticate() is True
    with pytest.raises(RuntimeError, match="rejected the credentials"):
        await client_with(handler, api_key="bad").authenticate()


@pytest.mark.asyncio
async def test_ingestion_reads_through_a_point_in_time_with_search_after_and_closes_it():
    calls = []
    page1 = [{**SYSMON_PROCESS, "_id": f"d{i}", "sort": [1788000930123 + i, i]} for i in range(2)]
    page2 = [{**SYSMON_PROCESS, "_id": "d9", "sort": [1788000939999, 9]}]

    def handler(request):
        body = json.loads(request.content) if request.content else {}
        calls.append((request.method, request.url.path, body))
        if request.url.path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "pit-1"})
        if request.url.path == "/_search":
            return httpx.Response(200, json={"pit_id": "pit-2", "hits": {"hits": page2 if "search_after" in body else page1}})
        return httpx.Response(200, json={"succeeded": True})

    client = client_with(handler, api_key="k")
    query = client.ingest_query("winlogbeat-*", EVENT_CODES)
    pages = [rows async for rows in client.search_raw_pages(query, earliest_time="1788000000", page_size=2, max_pages=5)]
    assert [len(p) for p in pages] == [2, 1]
    assert pages[0][0]["EventCode"] == "1"

    open_pit, first, second, close = calls
    assert open_pit[1] == "/winlogbeat-*/_pit"
    assert first[2]["pit"]["id"] == "pit-1" and first[2]["sort"][0] == {"@timestamp": "asc"} and "search_after" not in first[2]
    filters = first[2]["query"]["bool"]["filter"]
    assert filters[0]["range"]["@timestamp"] == {"gte": "1788000000", "format": "epoch_second", "lte": "now"}
    assert {"terms": {"winlog.event_id": [str(c) for c in EVENT_CODES]}} in filters[1]["bool"]["should"]
    assert second[2]["search_after"] == [1788000930124, 1] and second[2]["pit"]["id"] == "pit-2"  # each page continues from the PIT id Elastic returned
    assert close[0] == "DELETE" and close[1] == "/_pit" and close[2]["id"] == "pit-2"  # the PIT id Elastic last returned


@pytest.mark.asyncio
async def test_the_pit_is_closed_even_when_a_page_fails():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "p"})
        if request.url.path == "/_search":
            return httpx.Response(500)
        return httpx.Response(200, json={})

    client = client_with(handler)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        async for _ in client.search_raw_pages(client.ingest_query("w-*", EVENT_CODES), earliest_time="0"):
            pass
    assert ("DELETE", "/_pit") in calls


@pytest.mark.asyncio
async def test_a_full_ingestion_cycle_creates_an_alert_from_elastic_data():
    db = AsyncMongoMockClient()["elk"]

    def handler(request):
        if request.url.path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "p"})
        if request.url.path == "/_search":
            return httpx.Response(200, json={"hits": {"hits": [SYSMON_PROCESS]}})
        return httpx.Response(200, json={})

    service = IngestionService(db, "elk", splunk_factory=lambda: client_with(handler), detection_index="winlogbeat-*")
    new = await service.fetch_and_store_alerts()
    assert not service.errors
    assert [a["rule_name"] for a in new] == ["suspicious_powershell_execution"]
    assert new[0]["host"] == "WS-042" and new[0]["org_id"] == "elk"
    again = await IngestionService(db, "elk", splunk_factory=lambda: client_with(handler), detection_index="winlogbeat-*").fetch_and_store_alerts()
    assert again == []  # the same document does not create a second alert


@pytest.mark.asyncio
async def test_search_uses_a_query_string_over_the_configured_indexes_only():
    seen = {}

    def handler(request):
        seen.update(path=request.url.path, body=json.loads(request.content), params=dict(request.url.params))
        return httpx.Response(200, json={"hits": {"hits": [SYSMON_PROCESS]}})

    client = client_with(handler, api_key="k")
    client.indexes = ["winlogbeat-*", "logs-endpoint.*"]
    events = await client.search('host.name:"WS-042" AND winlog.event_id:1', earliest_time="-24h", limit=5000)
    assert seen["path"] == "/winlogbeat-*,logs-endpoint.*/_search"
    must = seen["body"]["query"]["bool"]["must"][0]["query_string"]
    assert must["query"].startswith("host.name") and must["allow_leading_wildcard"] is False
    assert seen["body"]["size"] == 1000 and seen["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-24h"
    assert events[0].hostname == "WS-042" and events[0].event_id == "1"


@pytest.mark.asyncio
async def test_list_indexes_and_alerts():
    def handler(request):
        if request.url.path == "/_cat/indices":
            return httpx.Response(200, json=[{"index": "b"}, {"index": "a"}])
        return httpx.Response(200, json={"hits": {"hits": [{"_id": "al1", "_source": {
            "@timestamp": "2026-10-28T10:00:00Z", "kibana.alert.rule.name": "Malware Prevention", "kibana.alert.severity": "HIGH",
            "kibana.alert.reason": "process x", "host": {"name": "h1"}, "user": {"name": "bob"}}}]}})

    client = client_with(handler)
    assert await client.list_indexes() == ["a", "b"]
    alert = (await client.list_alerts())[0]
    assert alert.title == "Malware Prevention" and alert.severity == "high" and alert.source_siem == "elastic" and alert.affected_hostname == "h1"


# ---------- tenant configuration and search endpoint ----------

async def call(db, who, method, path, json=None, router=tenants_module.router, prefix="/tenants"):
    app = FastAPI()
    app.include_router(router, prefix=prefix)

    async def _db():
        return db

    async def _user():
        return dict(who)

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path, json=json)


async def elastic_tenant(db, **siem):
    await db["tenants"].insert_one({"_id": "elk", "name": "Elk", "status": "active", "config": {}})
    body = {"reason": "use elastic", "siem": {"type": "elastic", "url": "https://es.corp.example:9200", "api_key": "es-key-123", "detection_index": "winlogbeat-*",
                                              "allowed_indexes": ["winlogbeat-*"], **siem}}
    return await call(db, ADMIN, "PUT", "/tenants/current/settings", body)


@pytest.mark.asyncio
async def test_a_tenant_can_choose_elastic_and_its_api_key_stays_secret():
    db = AsyncMongoMockClient()["t"]
    r = await elastic_tenant(db)
    assert r.status_code == 200, r.text
    view = r.json()["settings"]["siem"]
    assert view["type"] == "elastic" and view["configured"] and view["api_key_set"] and "es-key-123" not in r.text
    stored = (await db["tenants"].find_one({"_id": "elk"}))["config"]["siem"]
    assert stored["api_key_enc"].startswith("enc:v1:") and "es-key-123" not in str(stored)

    cfg = await svc.resolve_config(db, "elk")
    client = svc.siem_for(cfg)
    assert isinstance(client, ElasticClient) and client.api_key == "es-key-123" and client.indexes == ["winlogbeat-*"]
    assert (await call(db, ADMIN, "PUT", "/tenants/current/settings", {"reason": "typo", "siem": {"type": "qradar"}})).status_code == 422


@pytest.mark.asyncio
async def test_elastic_needs_a_key_or_a_username_and_password_to_count_as_configured():
    db = AsyncMongoMockClient()["t"]
    await db["tenants"].insert_one({"_id": "elk", "name": "Elk", "status": "active", "config": {}})
    await call(db, ADMIN, "PUT", "/tenants/current/settings", {"reason": "partial", "siem": {"type": "elastic", "url": "https://es.corp.example:9200"}})
    assert not (await svc.resolve_config(db, "elk")).siem.configured
    await call(db, ADMIN, "PUT", "/tenants/current/settings", {"reason": "basic", "siem": {"username": "svc", "password": "pw"}})
    assert (await svc.resolve_config(db, "elk")).siem.configured
    splunk_only = AsyncMongoMockClient()["s"]
    await splunk_only["tenants"].insert_one({"_id": "elk", "name": "E", "status": "active", "config": {}})
    await call(splunk_only, ADMIN, "PUT", "/tenants/current/settings", {"reason": "splunk", "siem": {"url": "https://s.example", "username": "svc"}})
    assert not (await svc.resolve_config(splunk_only, "elk")).siem.configured  # Splunk still needs a password


@pytest.mark.asyncio
async def test_connection_test_and_search_endpoint_use_the_tenants_elastic(monkeypatch):
    db = AsyncMongoMockClient()["t"]
    await elastic_tenant(db)
    seen = {}

    def handler(request):
        seen[request.url.path] = request.headers.get("authorization")
        if request.url.path == "/":
            return httpx.Response(200, json={"cluster_name": "prod"})
        return httpx.Response(200, json={"hits": {"hits": [SYSMON_PROCESS]}})

    def build(cfg):
        client = ElasticClient(url=cfg.siem.url, api_key=cfg.siem.api_key, indexes=["winlogbeat-*"])
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers={"Authorization": f"ApiKey {cfg.siem.api_key}"})
        return client

    monkeypatch.setattr(svc, "elastic_client", build)
    assert (await call(db, ADMIN, "POST", "/tenants/current/settings/siem/test")).json() == {"ok": True, "detail": "Authenticated"}
    assert seen["/"] == "ApiKey es-key-123"

    async def search(query):
        app = FastAPI()
        app.include_router(search_module.router, prefix="/search")

        async def _db():
            return db

        async def _user():
            return dict(ADMIN)

        app.dependency_overrides[get_db] = _db
        app.dependency_overrides[get_current_user] = _user
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            return await c.post("/search", json={"query": query})

    ok = await search('winlog.event_id:1 AND host.name:"WS-042"')
    assert ok.status_code == 200 and ok.json()["count"] == 1 and ok.json()["events"][0]["hostname"] == "WS-042"
    assert "/winlogbeat-*/_search" in seen
    assert (await search("   ")).status_code == 400
    assert (await search("x" * 1001)).status_code == 400
    audit = await db["audit_logs"].find_one({"action": "search.execute"})
    assert audit["entity_id"] == "elastic"
