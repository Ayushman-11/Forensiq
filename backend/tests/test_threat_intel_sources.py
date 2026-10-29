"""
Production-readiness 2.7: OTX, GreyNoise and MISP feed into the same corroboration rules as VirusTotal and AbuseIPDB.
"""

import json
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.agents import ioc_agent
from app.agents.recommendation_agent import _block_step, _malicious_by_ioc
from app.api.deps import get_current_user
from app.api.v1.endpoints import tenants as tenants_module
from app.database.session import get_db
from app.normalization.noise import NoiseFilter
from app.services import tenants as svc

ACME = {"id": "u1", "email": "admin@acme.example", "role": "admin", "org_id": "acme"}
GLOBEX = {"id": "u2", "email": "admin@globex.example", "role": "admin", "org_id": "globex"}
NOISE = NoiseFilter([], [], ["githubusercontent.com"])


def mock_http(monkeypatch, handler):
    calls = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    monkeypatch.setattr(ioc_agent, "_http", lambda timeout=10.0, verify=True: httpx.AsyncClient(transport=httpx.MockTransport(wrapped)))
    return calls


# ---------- OTX ----------

@pytest.mark.parametrize("pulses,verdict", [(0, "unknown"), (1, "suspicious"), (4, "suspicious"), (5, "malicious"), (40, "malicious")])
@pytest.mark.asyncio
async def test_otx_verdict_needs_a_quorum_of_pulses(monkeypatch, pulses, verdict):
    calls = mock_http(monkeypatch, lambda r: httpx.Response(200, json={"pulse_info": {"count": pulses, "pulses": [{"name": "Campaign X"}]}}))
    result = await ioc_agent._query_otx("203.0.113.9", "ip", api_key="otx-key")
    assert result.reputation == verdict and result.source == "OTX" and result.status == "ok"
    assert calls[0].url.path == "/api/v1/indicators/IPv4/203.0.113.9/general" and calls[0].headers["x-otx-api-key"] == "otx-key"


@pytest.mark.asyncio
async def test_otx_uses_the_right_indicator_kind_and_treats_404_as_no_information(monkeypatch):
    calls = mock_http(monkeypatch, lambda r: httpx.Response(404))
    for ioc, kind, expected in (("2001:db8::1", "ip", "IPv6"), ("evil.example", "domain", "domain"), ("a" * 64, "hash", "file")):
        result = await ioc_agent._query_otx(ioc, kind, api_key="k")
        assert result.reputation == "unknown" and result.status == "ok"
        assert f"/indicators/{expected}/" in calls[-1].url.path


@pytest.mark.asyncio
async def test_otx_errors_and_missing_keys_give_no_verdict(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(500))
    failed = await ioc_agent._query_otx("evil.example", "domain", api_key="k")
    assert failed.status == "error" and failed.reputation == "unknown"
    assert (await ioc_agent._query_otx("evil.example", "domain", api_key="")).status == "not_configured"


# ---------- GreyNoise ----------

@pytest.mark.parametrize("body,verdict", [
    ({"classification": "malicious", "noise": True}, "malicious"),
    ({"classification": "benign", "riot": True, "name": "Google"}, "benign"),
    ({"classification": "unknown", "riot": True}, "benign"),
    ({"classification": "unknown", "noise": True}, "suspicious"),
    ({"classification": "unknown", "noise": False, "riot": False}, "unknown"),
])
@pytest.mark.asyncio
async def test_greynoise_verdicts(monkeypatch, body, verdict):
    calls = mock_http(monkeypatch, lambda r: httpx.Response(200, json=body))
    result = await ioc_agent._query_greynoise("198.51.100.4", api_key="gn-key")
    assert result.reputation == verdict and result.source == "GreyNoise"
    assert calls[0].headers["key"] == "gn-key" and calls[0].url.path == "/v3/community/198.51.100.4"


@pytest.mark.asyncio
async def test_greynoise_not_observed_is_unknown_not_an_error(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(404, json={"message": "IP not observed"}))
    result = await ioc_agent._query_greynoise("198.51.100.4", api_key="k")
    assert result.status == "ok" and result.reputation == "unknown"


# ---------- MISP ----------

def misp_response(attributes):
    return lambda request: httpx.Response(200, json={"response": {"Attribute": attributes}})


@pytest.mark.asyncio
async def test_misp_actionable_attributes_are_malicious_and_warninglists_are_enforced(monkeypatch):
    calls = mock_http(monkeypatch, misp_response([{"event_id": "12", "to_ids": True, "value": "evil.example"}, {"event_id": "13", "to_ids": False}]))
    result = await ioc_agent._query_misp("evil.example", "domain", "https://misp.acme.example/", "misp-key")
    assert result.reputation == "malicious" and result.source == "MISP" and result.raw_response == {"attribute_count": 2, "actionable": 1, "event_ids": ["12", "13"]}
    request = calls[0]
    assert str(request.url) == "https://misp.acme.example/attributes/restSearch" and request.headers["authorization"] == "misp-key"
    body = json.loads(request.content)
    assert body["value"] == "evil.example" and body["enforceWarninglist"] is True and body["returnFormat"] == "json"


@pytest.mark.parametrize("attributes,verdict", [([], "unknown"), ([{"event_id": "1", "to_ids": False}], "suspicious")])
@pytest.mark.asyncio
async def test_misp_non_actionable_or_absent_matches(monkeypatch, attributes, verdict):
    mock_http(monkeypatch, misp_response(attributes))
    assert (await ioc_agent._query_misp("x.example", "domain", "https://m.example", "k")).reputation == verdict


@pytest.mark.asyncio
async def test_misp_failure_is_an_error_not_a_verdict(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(403))
    result = await ioc_agent._query_misp("x.example", "domain", "https://m.example", "k")
    assert result.status == "error" and result.reputation == "unknown"
    assert (await ioc_agent._query_misp("x.example", "domain", "", "")).status == "not_configured"


# ---------- per-tenant configuration and the enrichment node ----------

async def put(db, who, body):
    app = FastAPI()
    app.include_router(tenants_module.router, prefix="/tenants")

    async def _db():
        return db

    async def _user():
        return dict(who)

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.put("/tenants/current/settings", json={"reason": "feeds", **body})


@pytest.fixture
async def db():
    database = AsyncMongoMockClient()["ti"]
    await database["tenants"].insert_many([{"_id": "acme", "name": "Acme", "status": "active", "config": {}}, {"_id": "globex", "name": "Globex", "status": "active", "config": {}}])
    return database


@pytest.mark.asyncio
async def test_feed_credentials_are_per_tenant_write_only_and_misp_url_is_validated(db):
    r = await put(db, ACME, {"threat_intel": {"otx_api_key": "otx-acme", "greynoise_api_key": "gn-acme", "misp_url": "https://misp.acme.example", "misp_api_key": "misp-acme"}})
    assert r.status_code == 200, r.text
    assert not any(secret in r.text for secret in ("otx-acme", "gn-acme", "misp-acme"))
    ti = r.json()["settings"]["threat_intel"]
    assert ti["otx"] == {"configured": True, "source": "tenant"} and ti["misp"] == {"configured": True, "source": "tenant", "url": "https://misp.acme.example"}
    stored = str((await db["tenants"].find_one({"_id": "acme"}))["config"])
    assert "otx-acme" not in stored and "misp-acme" not in stored

    assert (await put(db, ACME, {"threat_intel": {"misp_url": "http://misp.acme.example"}})).status_code == 422
    assert (await put(db, ACME, {"threat_intel": {"misp_url": "https://169.254.169.254/"}})).status_code == 422
    assert (await put(db, ACME, {"threat_intel": {"misp_url": "https://user:pw@misp.acme.example"}})).status_code == 422
    cfg = await svc.threat_intel_config(db, "globex")
    assert cfg["otx"] == "" and cfg["misp_url"] == "" and cfg["misp_key"] == ""  # another tenant sees none of it


@pytest.mark.asyncio
async def test_misp_needs_its_url_and_key_together_and_can_fall_back_to_the_platform(db, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.MISP_URL", "https://misp.platform.example")
    monkeypatch.setattr("app.core.config.settings.MISP_API_KEY", "platform-misp-key")
    assert (await svc.threat_intel_config(db, "globex"))["misp_url"] == "https://misp.platform.example"
    await put(db, ACME, {"threat_intel": {"misp_api_key": "key-without-url"}})
    cfg = await svc.threat_intel_config(db, "acme")
    assert cfg["misp_url"] == "https://misp.platform.example" and cfg["misp_key"] == "platform-misp-key"  # a key alone never pairs with the platform URL
    monkeypatch.setattr("app.core.config.settings.TENANT_USE_PLATFORM_THREAT_INTEL", False)
    assert (await svc.threat_intel_config(db, "globex"))["misp_url"] == ""


@pytest.mark.asyncio
async def test_only_configured_feeds_are_asked_and_each_tenant_uses_its_own_keys(db, monkeypatch):
    await put(db, ACME, {"threat_intel": {"vt_api_key": "vt", "otx_api_key": "otx-acme", "greynoise_api_key": "gn-acme", "misp_url": "https://misp.acme.example", "misp_api_key": "misp-acme"}})
    await put(db, GLOBEX, {"threat_intel": {"vt_api_key": "vt-globex"}})
    for name in ("OTX_API_KEY", "GREYNOISE_API_KEY", "MISP_URL", "MISP_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.setattr(f"app.core.config.settings.{name}", "")
    asked = []

    async def fake(name):
        async def _inner(ioc, *a, **k):
            asked.append((name, ioc, k.get("api_key")))
            return ioc_agent.Enrichment(ioc=ioc, ioc_type="ip", reputation="unknown", threat_score=0, source=name, raw_response={})
        return _inner

    monkeypatch.setattr(ioc_agent, "_query_vt", await fake("VirusTotal"))
    monkeypatch.setattr(ioc_agent, "_query_abuseipdb", await fake("AbuseIPDB"))
    monkeypatch.setattr(ioc_agent, "_query_otx", await fake("OTX"))
    monkeypatch.setattr(ioc_agent, "_query_greynoise", await fake("GreyNoise"))

    async def misp(ioc, ioc_type, url, key):
        asked.append(("MISP", ioc, url, key))
        return ioc_agent.Enrichment(ioc=ioc, ioc_type=ioc_type, reputation="unknown", threat_score=0, source="MISP", raw_response={})

    monkeypatch.setattr(ioc_agent, "_query_misp", misp)
    monkeypatch.setattr(ioc_agent, "get_db", AsyncMock(return_value=db))

    state = lambda org, iocs: {"alert_data": {"org_id": org}, "extracted_iocs": iocs, "investigation_log": []}
    await ioc_agent.enrich_ioc_node(state("acme", ["203.0.113.9"]))
    assert {a[0] for a in asked} == {"VirusTotal", "AbuseIPDB", "OTX", "GreyNoise", "MISP"}
    assert ("MISP", "203.0.113.9", "https://misp.acme.example", "misp-acme") in asked
    asked.clear()
    await ioc_agent.enrich_ioc_node(state("globex", ["203.0.113.9"]))
    # The two core feeds are always asked (and say "not configured" when unset); optional feeds only when configured.
    assert {a[0] for a in asked} == {"VirusTotal", "AbuseIPDB"}
    assert ("VirusTotal", "203.0.113.9", "vt-globex") in asked
    asked.clear()
    await ioc_agent.enrich_ioc_node(state("acme", ["evil.example", "2001:db8::1"]))
    assert ("GreyNoise", "2001:db8::1", "gn-acme") not in asked and not [a for a in asked if a[0] == "GreyNoise"]  # IPv4 only


@pytest.mark.asyncio
async def test_a_tenants_private_misp_results_are_never_cached_or_shown_to_another_tenant(db, monkeypatch):
    await put(db, ACME, {"threat_intel": {"misp_url": "https://misp.acme.example", "misp_api_key": "misp-acme"}})
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "MISP_URL", "MISP_API_KEY"):
        monkeypatch.setattr(f"app.core.config.settings.{name}", "")
    mock_http(monkeypatch, misp_response([{"event_id": "7", "to_ids": True}]))
    monkeypatch.setattr(ioc_agent, "get_db", AsyncMock(return_value=db))

    acme = await ioc_agent.enrich_ioc_node({"alert_data": {"org_id": "acme"}, "extracted_iocs": ["evil.example"], "investigation_log": []})
    assert any(e["source"] == "MISP" and e["reputation"] == "malicious" for e in acme["enrichment_results"])
    assert await db["ioc_cache"].count_documents({"source": "MISP"}) == 0

    globex = await ioc_agent.enrich_ioc_node({"alert_data": {"org_id": "globex"}, "extracted_iocs": ["evil.example"], "investigation_log": []})
    assert not any(e["source"] == "MISP" for e in globex["enrichment_results"])


@pytest.mark.asyncio
async def test_public_feed_results_are_cached_and_reuse_respects_current_thresholds(monkeypatch):
    db = AsyncMongoMockClient()["cache"]
    calls = mock_http(monkeypatch, lambda r: httpx.Response(200, json={"pulse_info": {"count": 3, "pulses": []}}))
    first = await ioc_agent._query_otx("evil.example", "domain", db=db, api_key="k")
    assert first.reputation == "suspicious" and not first.cached
    monkeypatch.setattr("app.core.config.settings.OTX_MALICIOUS_MIN_PULSES", 3)
    second = await ioc_agent._query_otx("evil.example", "domain", db=db, api_key="k")
    assert second.cached and second.reputation == "malicious" and len(calls) == 1  # no second request; the new threshold applies


# ---------- corroboration ----------

def enrichment(source, verdict, ioc="203.0.113.9", raw=None):
    return {"ioc": ioc, "ioc_type": "ip", "reputation": verdict, "source": source, "status": "ok", "raw_response": raw or {}}


def test_two_independent_feeds_corroborate_and_one_does_not():
    two = _malicious_by_ioc([enrichment("OTX", "malicious"), enrichment("MISP", "malicious")])["203.0.113.9"]
    assert two["sources"] == {"OTX", "MISP"}
    assert "Block confirmed malicious" in _block_step(two, NOISE) and "Requires human approval" in _block_step(two, NOISE)
    one = _malicious_by_ioc([enrichment("GreyNoise", "malicious"), enrichment("OTX", "suspicious")])["203.0.113.9"]
    assert one["sources"] == {"GreyNoise"} and "against a second source" in _block_step(one, NOISE)
    same_feed_twice = _malicious_by_ioc([enrichment("OTX", "malicious"), enrichment("OTX", "malicious")])["203.0.113.9"]
    assert len(same_feed_twice["sources"]) == 1


def test_a_feed_that_errored_or_has_no_key_never_corroborates():
    results = [enrichment("OTX", "malicious"), {**enrichment("MISP", "malicious"), "status": "error"}, {**enrichment("GreyNoise", "malicious"), "status": "not_configured"}]
    assert _malicious_by_ioc(results)["203.0.113.9"]["sources"] == {"OTX"}


def test_greynoise_riot_overrules_corroboration_before_anyone_blocks_a_common_service():
    results = [enrichment("VirusTotal", "malicious"), enrichment("OTX", "malicious"), enrichment("GreyNoise", "benign", raw={"riot": True, "name": "Google"})]
    entry = _malicious_by_ioc(results)["203.0.113.9"]
    assert entry["benign_service"] is True
    step = _block_step(entry, NOISE)
    assert "do not block" in step and "RIOT" in step and "Block confirmed" not in step
