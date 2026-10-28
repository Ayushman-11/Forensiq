"""
Production-readiness 2.6: tenant management, per-tenant secrets and SIEM/threat-intel/noise settings,
and per-tenant poller scheduling. Isolation across every endpoint is in test_tenant_isolation.py.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.agents import ioc_agent
from app.api.deps import get_current_user
from app.api.v1.endpoints import alerts as alerts_module
from app.api.v1.endpoints import auth as auth_module
from app.api.v1.endpoints import search as search_module
from app.api.v1.endpoints import tenants as tenants_module
from app.core.security import create_access_token
from app.database.session import get_db
from app.services import poller as poller_module
from app.services import tenants as svc
from app.services.ingestion import build_query
from app.services.poller import AlertPoller, lease_name

PLATFORM_ADMIN = {"id": "p1", "email": "root@platform.example", "role": "admin", "org_id": "default"}
ACME_ADMIN = {"id": "u-acme", "email": "admin@acme.example", "role": "admin", "org_id": "acme"}
GLOBEX_ADMIN = {"id": "u-globex", "email": "admin@globex.example", "role": "admin", "org_id": "globex"}
ACME_ANALYST = {"id": "u-acme-2", "email": "l1@acme.example", "role": "soc_analyst", "org_id": "acme"}
SIEM = {"url": "https://splunk.acme.example:8089", "username": "forensiq", "password": "s3cret-splunk-pw"}


@pytest.fixture
def db():
    return AsyncMongoMockClient()["tenants"]


async def call(db, who, method, path, json=None, router=tenants_module.router, prefix="/tenants", real_auth=False):
    app = FastAPI()
    app.include_router(router, prefix=prefix)

    async def _db():
        return db

    async def _user():
        return dict(who)

    app.dependency_overrides[get_db] = _db
    if not real_auth:
        app.dependency_overrides[get_current_user] = _user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path, json=json, headers=who if real_auth else None)


async def new_tenant(db, org="acme", admin_email="admin@acme.example"):
    return await call(db, PLATFORM_ADMIN, "POST", "/tenants", {"id": org, "name": f"{org.title()} Corp", "admin_email": admin_email, "admin_password": "a-long-password-1"})


# ---------- secrets at rest ----------

def test_secrets_are_encrypted_round_trip_and_survive_key_rotation(monkeypatch):
    stored = svc.encrypt_secret("hunter2-hunter2")
    assert stored.startswith("enc:v1:") and "hunter2" not in stored
    assert stored != svc.encrypt_secret("hunter2-hunter2")  # fresh nonce each time
    assert svc.decrypt_secret(stored) == "hunter2-hunter2"
    assert svc.decrypt_secret("") == "" and svc.decrypt_secret("plaintext-not-encrypted") == ""

    old_key = "the-old-secret-key-that-was-in-use-for-ages"
    monkeypatch.setattr("app.core.config.settings.SECRET_KEY", old_key)
    monkeypatch.setattr("app.core.config.settings.PREVIOUS_SECRET_KEY", None)
    before = svc.encrypt_secret("rotating-secret")
    monkeypatch.setattr("app.core.config.settings.SECRET_KEY", "a-brand-new-secret-key-after-the-rotation-xx")
    assert svc.decrypt_secret(before) == ""  # without the previous key it is unreadable, never garbage
    monkeypatch.setattr("app.core.config.settings.PREVIOUS_SECRET_KEY", old_key)
    assert svc.decrypt_secret(before) == "rotating-secret"


@pytest.mark.parametrize("url", [
    "http://splunk.corp.example:8089", "https://user:pw@splunk.corp.example", "https://localhost:8089", "https://127.0.0.1:8089",
    "https://169.254.169.254/latest/meta-data", "https://metadata/", "https://0.0.0.0", "https://[::1]:8089", "https://x.example:99999", "ftp://x.example", "splunk.corp.example", "",
])
def test_siem_urls_that_could_reach_the_server_itself_are_refused(url):
    with pytest.raises(svc.TenantError):
        svc.validate_siem_url(url)


def test_normal_siem_urls_are_accepted():
    assert svc.validate_siem_url("https://splunk.corp.example:8089/") == "https://splunk.corp.example:8089"
    assert svc.validate_siem_url("https://10.20.30.40:8089") == "https://10.20.30.40:8089"  # private SIEMs are normal


# ---------- tenant lifecycle (platform admin) ----------

@pytest.mark.asyncio
async def test_platform_admin_creates_a_tenant_with_its_first_admin(db):
    r = await new_tenant(db)
    assert r.status_code == 201 and r.json()["id"] == "acme"
    admin = await db["users"].find_one({"email": "admin@acme.example"})
    assert admin["org_id"] == "acme" and admin["role"] == "admin" and admin["password_hash"] != "a-long-password-1"
    assert (await db["tenants"].find_one({"_id": "acme"}))["status"] == "active"
    assert await db["audit_logs"].count_documents({"action": "tenant.created", "org_id": "acme"}) == 1

    assert (await new_tenant(db)).status_code == 409  # id taken
    assert (await new_tenant(db, org="other", admin_email="admin@acme.example")).status_code == 409  # email taken
    for bad in ("Acme Corp", "a", "-acme", "admin", "current", "tenants", "x" * 41, "acme_corp"):
        r = await call(db, PLATFORM_ADMIN, "POST", "/tenants", {"id": bad, "name": "Bad", "admin_email": "n@x.example", "admin_password": "a-long-password-1"})
        assert r.status_code == 422, bad
    assert (await call(db, PLATFORM_ADMIN, "POST", "/tenants", {"id": "okid", "name": "Ok", "admin_email": "n@x.example", "admin_password": "short"})).status_code == 422
    assert (await call(db, ACME_ADMIN, "POST", "/tenants", {"id": "evil", "name": "Evil", "admin_email": "e@evil.example", "admin_password": "a-long-password-1"})).status_code == 403
    assert await db["tenants"].count_documents({}) == 1


@pytest.mark.asyncio
async def test_listing_shows_registered_and_legacy_tenants_with_runtime_status(db):
    await new_tenant(db)
    await db["users"].insert_one({"_id": "old", "email": "o@legacy.example", "org_id": "legacy", "role": "admin"})
    await db["tenant_runtime"].insert_one({"_id": "acme", "last_poll_at": datetime.now(timezone.utc), "last_error": "fetch"})
    rows = {r["id"]: r for r in (await call(db, PLATFORM_ADMIN, "GET", "/tenants")).json()}
    assert rows["acme"]["registered"] and rows["acme"]["users"] == 1 and rows["acme"]["last_error"] == "fetch"
    assert rows["legacy"]["registered"] is False
    assert (await call(db, ACME_ADMIN, "GET", "/tenants")).status_code == 403


@pytest.mark.asyncio
async def test_suspending_a_tenant_blocks_its_users_everywhere_and_ends_sessions(db):
    await new_tenant(db)
    admin = await db["users"].find_one({"email": "admin@acme.example"})
    await db["sessions"].insert_one({"_id": "s1", "user_id": admin["_id"]})
    token = create_access_token(user_id=str(admin["_id"]), email=admin["email"], role="admin", org_id="acme")
    bearer = {"Authorization": f"Bearer {token}"}

    async def me():
        app = FastAPI()
        app.include_router(tenants_module.router, prefix="/tenants")
        app.dependency_overrides[get_db] = lambda: db

        async def _db():
            return db

        app.dependency_overrides[get_db] = _db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            return await c.get("/tenants/current/settings", headers=bearer)

    assert (await me()).status_code == 200
    r = await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {"status": "suspended"})
    assert r.status_code == 200
    blocked = await me()
    assert blocked.status_code == 403 and "suspended" in blocked.json()["detail"]
    assert await db["sessions"].count_documents({}) == 0
    assert await db["audit_logs"].count_documents({"action": "tenant.suspended"}) >= 1

    assert (await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {"status": "active"})).status_code == 200
    assert (await me()).status_code == 200


@pytest.mark.asyncio
async def test_users_of_a_suspended_tenant_cannot_log_in_and_can_again_once_reactivated(db):
    await new_tenant(db)
    login = lambda: call(db, {}, "POST", "/auth/login", {"email": "admin@acme.example", "password": "a-long-password-1"}, router=auth_module.router, prefix="/auth", real_auth=True)
    assert (await login()).status_code == 200
    await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {"status": "suspended"})
    blocked = await login()
    assert blocked.status_code == 403 and "suspended" in blocked.json()["detail"]
    await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {"status": "active"})
    assert (await login()).status_code == 200


@pytest.mark.asyncio
async def test_platform_and_own_tenant_cannot_be_suspended_and_bad_patches_are_rejected(db):
    await new_tenant(db)
    await db["tenants"].insert_one({"_id": "default", "name": "Platform", "status": "active"})
    assert (await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/default", {"status": "suspended"})).status_code == 409
    assert (await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {"status": "deleted"})).status_code == 422
    assert (await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {})).status_code == 422
    assert (await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/nope", {"name": "Nope"})).status_code == 404
    assert (await call(db, PLATFORM_ADMIN, "PATCH", "/tenants/acme", {"name": "Acme Inc"})).json()["name"] == "Acme Inc"


# ---------- per-tenant settings ----------

@pytest.mark.asyncio
async def test_tenant_admin_sets_siem_and_secrets_are_write_only_and_encrypted(db):
    await new_tenant(db)
    body = {"siem": {**SIEM, "detection_index": "windows_sec", "allowed_indexes": ["windows_sec", "linux"], "poll_interval_seconds": 60}, "threat_intel": {"vt_api_key": "vt-key-acme-123"},
            "reason": "onboarding"}
    r = await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", body)
    assert r.status_code == 200, r.text
    text = r.text
    assert "s3cret-splunk-pw" not in text and "vt-key-acme-123" not in text
    view = r.json()["settings"]
    assert view["siem"]["configured"] and view["siem"]["password_set"] and view["siem"]["source"] == "tenant" and view["siem"]["poll_interval_seconds"] == 60
    assert view["threat_intel"]["virustotal"] == {"configured": True, "source": "tenant"}
    assert sorted(r.json()["changed"]) == sorted(["siem.url", "siem.username", "siem.password", "siem.detection_index", "siem.allowed_indexes", "siem.poll_interval_seconds", "threat_intel.vt_api_key"])

    stored = (await db["tenants"].find_one({"_id": "acme"}))["config"]
    assert stored["siem"]["password_enc"].startswith("enc:v1:") and "s3cret" not in str(stored) and "vt-key-acme-123" not in str(stored)
    assert (await call(db, ACME_ADMIN, "GET", "/tenants/current/settings")).text.count("s3cret") == 0
    audit = [a async for a in db["audit_logs"].find({"action": "tenant.settings_updated"})]
    assert audit and "s3cret" not in str(audit) and "vt-key" not in str(audit) and audit[0]["metadata"]["reason"] == "onboarding"

    # Partial update keeps the stored secret; empty string clears it.
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"siem": {"poll_interval_seconds": 120}, "reason": "slower"})
    assert (await svc.resolve_config(db, "acme")).siem.password == "s3cret-splunk-pw"
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"siem": {"password": ""}, "reason": "rotate out"})
    cfg = await svc.resolve_config(db, "acme")
    assert cfg.siem.password == "" and cfg.siem.configured is False


@pytest.mark.asyncio
async def test_settings_validation(db):
    await new_tenant(db)
    put = lambda body: call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "test", **body})
    assert (await put({"siem": {"url": "http://splunk.example"}})).status_code == 422
    assert (await put({"siem": {"url": "https://169.254.169.254"}})).status_code == 422
    assert (await put({"siem": {"poll_interval_seconds": 1}})).status_code == 422
    assert (await put({"siem": {"poll_interval_seconds": 99999}})).status_code == 422
    assert (await put({"siem": {"detection_index": "bad index!"}})).status_code == 422
    assert (await put({"siem": {"allowed_indexes": ["ok", "no spaces allowed"]}})).status_code == 422
    assert (await put({"noise": {"suppress": [{"name": "x", "where": {"command_line_regex": "("}}]}})).status_code == 422
    assert (await put({"noise": {"suppress": [{"name": "x", "where": {"unknown_key": 1}}]}})).status_code == 422
    assert (await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"siem": {"url": "https://s.example"}})).status_code == 422  # reason required
    assert (await call(db, ACME_ANALYST, "PUT", "/tenants/current/settings", {"reason": "x", "siem": {"url": "https://s.example"}})).status_code == 403
    assert (await db["tenants"].find_one({"_id": "acme"}))["config"] == {}


@pytest.mark.asyncio
async def test_noise_policy_is_per_tenant_and_resettable(db):
    await new_tenant(db)
    await new_tenant(db, org="globex", admin_email="admin@globex.example")
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "noise", "noise": {"benign_domains": ["intranet.acme.example"]}})
    acme, globex = await svc.resolve_config(db, "acme"), await svc.resolve_config(db, "globex")
    assert svc.noise_filter(acme).is_benign_domain("wiki.intranet.acme.example")
    assert not svc.noise_filter(globex).is_benign_domain("wiki.intranet.acme.example")  # other tenants keep the platform policy
    assert acme.noise and globex.noise is None
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "back", "reset_noise": True})
    assert (await svc.resolve_config(db, "acme")).noise is None


@pytest.mark.asyncio
async def test_platform_admin_edits_any_tenant_and_both_trails_record_it(db):
    await new_tenant(db)
    r = await call(db, PLATFORM_ADMIN, "PUT", "/tenants/acme/settings", {"reason": "support request #123", "siem": SIEM})
    assert r.status_code == 200
    orgs = sorted([a["org_id"] async for a in db["audit_logs"].find({"action": "tenant.settings_updated"})])
    assert orgs == ["acme", "default"]  # the tenant can see who changed its settings
    assert (await call(db, PLATFORM_ADMIN, "PUT", "/tenants/ghost/settings", {"reason": "support ticket", "siem": SIEM})).status_code == 404
    assert (await call(db, ACME_ADMIN, "GET", "/tenants/globex/settings")).status_code == 403


@pytest.mark.asyncio
async def test_siem_connection_test_reports_success_and_failure_without_leaking_credentials(db, monkeypatch):
    await new_tenant(db)
    assert (await call(db, ACME_ADMIN, "POST", "/tenants/current/settings/siem/test")).status_code == 409  # nothing configured
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "going live", "siem": SIEM})

    class Fake:
        def __init__(self, ok):
            self.ok = ok
            self.closed = False

        async def authenticate(self):
            if not self.ok:
                raise RuntimeError("Splunk Authentication Failed: 401")
            return True

        async def close(self):
            self.closed = True

    fake = Fake(True)
    monkeypatch.setattr(svc, "splunk_client", lambda cfg: fake)
    assert (await call(db, ACME_ADMIN, "POST", "/tenants/current/settings/siem/test")).json() == {"ok": True, "detail": "Authenticated"}
    assert fake.closed
    monkeypatch.setattr(svc, "splunk_client", lambda cfg: Fake(False))
    r = (await call(db, ACME_ADMIN, "POST", "/tenants/current/settings/siem/test")).json()
    assert r["ok"] is False and "401" in r["detail"] and "s3cret" not in r["detail"]


# ---------- effective configuration ----------

@pytest.mark.asyncio
async def test_a_tenant_without_a_siem_never_falls_back_to_the_platform_siem(db, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.SPLUNK_URL", "https://platform-splunk.example:8089")
    monkeypatch.setattr("app.core.config.settings.SPLUNK_USERNAME", "platform")
    monkeypatch.setattr("app.core.config.settings.SPLUNK_PASSWORD", "platform-pw")
    await new_tenant(db)
    platform, acme = await svc.resolve_config(db, "default"), await svc.resolve_config(db, "acme")
    assert platform.siem.configured and platform.siem.url == "https://platform-splunk.example:8089" and platform.siem.source == "platform"
    assert not acme.siem.configured and acme.siem.url == "" and acme.siem.password == ""
    client = svc.siem_for(acme)
    assert isinstance(client, svc.UnconfiguredSiem)
    with pytest.raises(RuntimeError):
        await client.search(query="index=main")
    assert svc.splunk_client(platform).base_url == "https://platform-splunk.example:8089"


@pytest.mark.asyncio
async def test_threat_intel_keys_resolve_tenant_then_platform_then_none(db, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.VT_API_KEY", "platform-vt")
    monkeypatch.setattr("app.core.config.settings.ABUSEIPDB_API_KEY", "")
    await new_tenant(db)
    await new_tenant(db, org="globex", admin_email="admin@globex.example")
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "keys", "threat_intel": {"vt_api_key": "acme-vt", "abuseipdb_api_key": "acme-abuse"}})
    assert await svc.threat_intel_keys(db, "acme") == ("acme-vt", "acme-abuse")
    assert await svc.threat_intel_keys(db, "globex") == ("platform-vt", "")
    view = svc.public_view(await svc.resolve_config(db, "globex"))["threat_intel"]
    assert view["virustotal"]["source"] == "platform" and view["abuseipdb"] == {"configured": False, "source": "none"}
    monkeypatch.setattr("app.core.config.settings.TENANT_USE_PLATFORM_THREAT_INTEL", False)
    assert await svc.threat_intel_keys(db, "globex") == ("", "")
    assert await svc.threat_intel_keys(db, "default") == ("platform-vt", "")  # the platform always uses its own


@pytest.mark.asyncio
async def test_enrichment_uses_the_alerts_own_tenant_keys(db, monkeypatch):
    await new_tenant(db)
    await new_tenant(db, org="globex", admin_email="admin@globex.example")
    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "keys", "threat_intel": {"vt_api_key": "acme-vt"}})
    await call(db, GLOBEX_ADMIN, "PUT", "/tenants/current/settings", {"reason": "keys", "threat_intel": {"vt_api_key": "globex-vt"}})
    monkeypatch.setattr("app.core.config.settings.VT_API_KEY", "")
    seen = []

    async def fake_vt(ioc, ioc_type, db=None, api_key=None):
        seen.append(api_key)
        return ioc_agent._unavailable(ioc, ioc_type, "VirusTotal", "not_configured", "test")

    monkeypatch.setattr(ioc_agent, "_query_vt", fake_vt)
    monkeypatch.setattr(ioc_agent, "get_db", AsyncMock(return_value=db))
    for org in ("acme", "globex"):
        await ioc_agent.enrich_ioc_node({"alert_data": {"org_id": org}, "extracted_iocs": ["evil.example"], "investigation_log": []})
    assert seen == ["acme-vt", "globex-vt"]


def test_detection_index_comes_from_the_tenant():
    assert "index=windows_sec |" in build_query("windows_sec")
    assert "index=" in build_query()


@pytest.mark.asyncio
async def test_manual_ingest_and_search_use_the_tenants_own_siem_settings(db, monkeypatch):
    await new_tenant(db)
    # No SIEM: ingest refuses instead of using the platform's.
    ingest = await call(db, ACME_ADMIN, "POST", "/alerts/ingest", router=alerts_module.router, prefix="/alerts")
    assert ingest.status_code == 409 and "No SIEM" in ingest.json()["detail"]

    await call(db, ACME_ADMIN, "PUT", "/tenants/current/settings", {"reason": "going live", "siem": {**SIEM, "detection_index": "acme_idx", "allowed_indexes": ["acme_idx"]}})
    built = {}

    class FakeIngestion:
        errors: list = []
        total_fetched = 0
        rules_run = 0

        def __init__(self, db, org_id, **kwargs):
            built.update(org=org_id, url=kwargs["splunk_factory"]().base_url, index=kwargs["detection_index"])

        async def fetch_and_store_alerts(self):
            return []

    monkeypatch.setattr(alerts_module, "IngestionService", FakeIngestion)
    r = await call(db, ACME_ADMIN, "POST", "/alerts/ingest", router=alerts_module.router, prefix="/alerts")
    assert r.status_code == 200
    assert built == {"org": "acme", "url": "https://splunk.acme.example:8089", "index": "acme_idx"}

    # Search: the tenant's allowed indexes apply; the platform's do not.
    bad = await call(db, ACME_ADMIN, "POST", "/search", {"query": "search index=windows EventCode=1"}, router=search_module.router, prefix="/search")
    assert bad.status_code == 400


# ---------- per-tenant poller ----------

class FakeIngestion:
    runs: list = []
    fail_for: set = set()

    def __init__(self, db, org_id="default", **kwargs):
        self.org, self.kwargs, self.errors = org_id, kwargs, []

    async def fetch_and_store_alerts(self):
        FakeIngestion.runs.append((self.org, self.kwargs["splunk_factory"]().base_url, self.kwargs["detection_index"]))
        if self.org in FakeIngestion.fail_for:
            raise RuntimeError("splunk down")
        return [{"_id": f"{self.org}-a1", "org_id": self.org, "rule_name": "r"}]


@pytest.fixture
def fake_ingestion(monkeypatch):
    FakeIngestion.runs, FakeIngestion.fail_for = [], set()
    monkeypatch.setattr(poller_module, "IngestionService", FakeIngestion)
    return FakeIngestion


async def configure(db, org, **siem):
    await db["tenants"].update_one({"_id": org}, {"$set": {"config.siem": {"username": "svc", "password_enc": svc.encrypt_secret("pw"), **siem}}})


@pytest.mark.asyncio
async def test_each_tenant_is_polled_with_its_own_credentials_index_and_lease(db, fake_ingestion):
    await new_tenant(db)
    await new_tenant(db, org="globex", admin_email="admin@globex.example")
    await configure(db, "acme", url="https://splunk.acme.example", detection_index="acme_idx")
    await configure(db, "globex", url="https://splunk.globex.example", detection_index="globex_idx", poll_interval_seconds=300)
    poller = AlertPoller(db, interval_seconds=30)
    poller._investigate_alert = AsyncMock()

    await poller._poll_once()
    await asyncio.gather(*list(poller._tasks))
    runs = {org: (url, index) for org, url, index in fake_ingestion.runs}
    assert runs["acme"] == ("https://splunk.acme.example", "acme_idx")
    assert runs["globex"] == ("https://splunk.globex.example", "globex_idx")
    assert "default" in runs  # the platform tenant keeps being polled with the platform SIEM
    assert {l["_id"] async for l in db["leases"].find({})} == {"alert_poller", "alert_poller:acme", "alert_poller:globex"}
    assert lease_name("default") == "alert_poller"
    investigated = sorted(c.args[0]["org_id"] for c in poller._investigate_alert.await_args_list)
    assert investigated == ["acme", "default", "globex"]  # each alert is investigated as its own tenant


@pytest.mark.asyncio
async def test_each_tenant_follows_its_own_interval(db, fake_ingestion):
    await new_tenant(db)
    await configure(db, "acme", url="https://splunk.acme.example", poll_interval_seconds=300)
    poller = AlertPoller(db, interval_seconds=30)
    poller._investigate_alert = AsyncMock()
    await poller._poll_once()
    first = len(fake_ingestion.runs)
    await poller._poll_once()  # nothing is due yet
    assert len(fake_ingestion.runs) == first
    poller._next_run["acme"] = 0  # acme's interval elapsed; the platform's has not
    await poller._poll_once()
    assert [org for org, *_ in fake_ingestion.runs[first:]] == ["acme"]


@pytest.mark.asyncio
async def test_one_tenants_failing_siem_does_not_stop_the_others_and_backs_off(db, fake_ingestion):
    await new_tenant(db)
    await configure(db, "acme", url="https://splunk.acme.example", poll_interval_seconds=10)
    fake_ingestion.fail_for = {"acme"}
    poller = AlertPoller(db, interval_seconds=30)
    poller._investigate_alert = AsyncMock()

    await poller._poll_once()
    runtime = await db["tenant_runtime"].find_one({"_id": "acme"})
    assert runtime["consecutive_failures"] == 1 and "splunk down" in runtime["last_error"] and "last_success_at" not in runtime
    assert (await db["tenant_runtime"].find_one({"_id": "default"}))["last_error"] is None  # the platform tenant was unaffected
    first_gap = poller._next_run["acme"]
    poller._next_run["acme"] = 0
    await poller._poll_once()
    assert (await db["tenant_runtime"].find_one({"_id": "acme"}))["consecutive_failures"] == 2
    assert poller._next_run["acme"] > first_gap - 1  # later failures wait longer, up to a cap

    fake_ingestion.fail_for = set()
    poller._next_run["acme"] = 0
    await poller._poll_once()
    healed = await db["tenant_runtime"].find_one({"_id": "acme"})
    assert healed["consecutive_failures"] == 0 and healed["last_error"] is None and healed["last_success_at"]


@pytest.mark.asyncio
async def test_suspended_disabled_and_unconfigured_tenants_are_not_polled(db, fake_ingestion):
    for org in ("acme", "globex", "initech"):
        await new_tenant(db, org=org, admin_email=f"admin@{org}.example")
    await configure(db, "acme", url="https://splunk.acme.example")
    await configure(db, "globex", url="https://splunk.globex.example", enabled=False)
    await configure(db, "initech", url="https://splunk.initech.example")
    await db["tenants"].update_one({"_id": "initech"}, {"$set": {"status": "suspended"}})
    await db["tenants"].insert_one({"_id": "bare", "name": "Bare", "status": "active", "config": {"siem": {"username": "svc"}}})  # no URL or password
    poller = AlertPoller(db, interval_seconds=30)
    poller._investigate_alert = AsyncMock()
    await poller._poll_once()
    assert {org for org, *_ in fake_ingestion.runs} == {"default", "acme"}


@pytest.mark.asyncio
async def test_stop_releases_every_tenant_lease(db, fake_ingestion):
    await new_tenant(db)
    await configure(db, "acme", url="https://splunk.acme.example")
    poller = AlertPoller(db, interval_seconds=30)
    poller._investigate_alert = AsyncMock()
    await poller._poll_once()
    assert await db["leases"].count_documents({}) == 2
    await poller.stop()
    assert await db["leases"].count_documents({}) == 0
