import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
import httpx
import respx
from app.agents.ioc_agent import (
    _get_ioc_type,
    _abuseipdb_verdict,
    _get_cached_enrichment,
    _query_abuseipdb,
    _query_vt,
    _save_cached_enrichment,
    _vt_verdict,
    enrich_ioc_node,
    Enrichment,
)
from app.core.config import settings
from app.agents.state import AgentState


def test_get_ioc_type():
    assert _get_ioc_type("192.168.1.100") == "ip"
    assert _get_ioc_type("10.0.0.1") == "ip"
    assert _get_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert _get_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"
    assert _get_ioc_type("malicious-c2.example.com") == "domain"
    assert _get_ioc_type("raw.githubusercontent.com") == "domain"


def test_one_vt_engine_is_suspicious_not_malicious():
    # raw.githubusercontent.com in the 2026-10-28 audit: 1 of 92 engines.
    assert _vt_verdict({"malicious": 1, "suspicious": 0, "harmless": 58, "undetected": 33}) == "suspicious"
    assert _vt_verdict({"malicious": settings.VT_MALICIOUS_MIN_ENGINES, "harmless": 50}) == "malicious"
    assert _vt_verdict({"malicious": 0, "suspicious": 0, "harmless": 60}) == "benign"
    assert _vt_verdict({"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 70}) == "unknown"


def test_abuseipdb_thresholds():
    assert _abuseipdb_verdict(100) == "malicious"
    assert _abuseipdb_verdict(50) == "suspicious"
    assert _abuseipdb_verdict(0) == "benign"


@pytest.mark.asyncio
async def test_missing_keys_give_no_verdict_and_are_not_cached(monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", "")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    db = MagicMock()
    db.__getitem__.return_value.find_one = AsyncMock(return_value=None)
    db.__getitem__.return_value.update_one = AsyncMock()

    # 185.199.108.133 is GitHub; the old mock rated every 185.* IP malicious.
    vt = await _query_vt("185.199.108.133", "ip", db=db)
    abuse = await _query_abuseipdb("185.199.108.133", db=db)

    for res in (vt, abuse):
        assert res.status == "not_configured"
        assert res.reputation == "unknown" and res.threat_score == 0
        assert "Mock" not in res.source
    db.__getitem__.return_value.update_one.assert_not_called()


@pytest.mark.asyncio
@respx.mock
async def test_feed_errors_give_no_verdict(monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", "k")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "k")
    respx.get(url__startswith="https://www.virustotal.com/").mock(return_value=httpx.Response(429))
    respx.get(url__startswith="https://api.abuseipdb.com/").mock(side_effect=httpx.ConnectTimeout("slow"))

    vt = await _query_vt("evil.example.com", "domain", db=None)
    abuse = await _query_abuseipdb("45.33.32.1", db=None)

    assert (vt.status, vt.reputation) == ("error", "unknown")
    assert (abuse.status, abuse.reputation) == ("error", "unknown")


@pytest.mark.asyncio
async def test_cached_verdict_is_rederived_with_current_thresholds():
    db = MagicMock()
    stale = Enrichment(
        ioc="raw.githubusercontent.com", ioc_type="domain", reputation="malicious", threat_score=1,
        source="VirusTotal", raw_response={"malicious": 1, "suspicious": 0, "harmless": 58, "undetected": 33},
    )
    db.__getitem__.return_value.find_one = AsyncMock(return_value={
        "cached_at": datetime.now(timezone.utc), "data": stale.model_dump(),
    })
    cached = await _get_cached_enrichment(db, "raw.githubusercontent.com", "VirusTotal")
    assert cached.reputation == "suspicious"


@pytest.mark.asyncio
async def test_ioc_cache_save_and_retrieve():
    # Mock motor db
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection

    enrichment = Enrichment(
        ioc="192.0.2.1",
        ioc_type="ip",
        reputation="suspicious",
        threat_score=60,
        source="AbuseIPDB",
        raw_response={"abuseConfidenceScore": 60},
        cached=False,
    )

    mock_collection.update_one = AsyncMock()
    await _save_cached_enrichment(mock_db, enrichment)
    assert mock_collection.update_one.called
    call_args = mock_collection.update_one.call_args
    assert call_args[0][0] == {"ioc": "192.0.2.1", "source": "AbuseIPDB"}

    # Now mock cache hit unexpired
    mock_collection.find_one = AsyncMock(return_value={
        "ioc": "192.0.2.1",
        "source": "AbuseIPDB",
        "cached_at": datetime.now(timezone.utc) - timedelta(hours=2),
        "data": enrichment.model_dump(),
    })

    cached_res = await _get_cached_enrichment(mock_db, "192.0.2.1", "AbuseIPDB")
    assert cached_res is not None
    assert cached_res.ioc == "192.0.2.1"
    assert cached_res.cached is True

    # Now mock expired cache (e.g. 48 hours ago with 24h TTL)
    mock_collection.find_one = AsyncMock(return_value={
        "ioc": "192.0.2.1",
        "source": "AbuseIPDB",
        "cached_at": datetime.now(timezone.utc) - timedelta(hours=48),
        "data": enrichment.model_dump(),
    })

    expired_res = await _get_cached_enrichment(mock_db, "192.0.2.1", "AbuseIPDB")
    assert expired_res is None


@pytest.mark.asyncio
async def test_enrich_ioc_node_reports_unavailable_feeds(monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", "")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr("app.agents.ioc_agent.get_db", AsyncMock(side_effect=RuntimeError("no db")))
    state: AgentState = {
        "alert_data": {"_id": "test-alert"},
        "extracted_iocs": ["45.33.32.1", "safe.internal.lan"],
        "investigation_log": ["Initial log"],
    }

    result = await enrich_ioc_node(state)

    enrichments = result["enrichment_results"]
    assert len(enrichments) == 3  # VT for both IOCs, AbuseIPDB for the IP
    assert all(e["status"] == "not_configured" and e["reputation"] == "unknown" for e in enrichments)
    log_entry = result["investigation_log"][-1]
    assert "0 malicious" in log_entry
    assert "No verdict from: AbuseIPDB (not_configured), VirusTotal (not_configured)" in log_entry
