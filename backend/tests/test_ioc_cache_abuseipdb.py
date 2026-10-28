from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.ioc_agent import (
    Enrichment,
    _get_cached_enrichment,
    _get_ioc_type,
    _save_cached_enrichment,
    enrich_ioc_node,
)
from app.agents.state import AgentState
from app.core.config import settings


def test_get_ioc_type():
    assert _get_ioc_type("192.168.1.100") == "ip"
    assert _get_ioc_type("10.0.0.1") == "ip"
    assert _get_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert (
        _get_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"
    )
    assert _get_ioc_type("malicious-c2.example.com") == "domain"
    assert _get_ioc_type("raw.githubusercontent.com") == "domain"


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
    mock_collection.find_one = AsyncMock(
        return_value={
            "ioc": "192.0.2.1",
            "source": "AbuseIPDB",
            "cached_at": datetime.now(UTC) - timedelta(hours=2),
            "data": enrichment.model_dump(),
        }
    )

    cached_res = await _get_cached_enrichment(mock_db, "192.0.2.1", "AbuseIPDB")
    assert cached_res is not None
    assert cached_res.ioc == "192.0.2.1"
    assert cached_res.cached is True

    # Now mock expired cache (e.g. 48 hours ago with 24h TTL)
    mock_collection.find_one = AsyncMock(
        return_value={
            "ioc": "192.0.2.1",
            "source": "AbuseIPDB",
            "cached_at": datetime.now(UTC) - timedelta(hours=48),
            "data": enrichment.model_dump(),
        }
    )

    expired_res = await _get_cached_enrichment(mock_db, "192.0.2.1", "AbuseIPDB")
    assert expired_res is None


@pytest.mark.asyncio
async def test_enrich_ioc_node_unconfigured_feeds_yield_no_verdict(monkeypatch):
    monkeypatch.setattr(settings, "VT_API_KEY", None)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)

    state: AgentState = {
        "alert_data": {"_id": "test-alert"},
        "extracted_iocs": ["45.33.32.1", "safe.internal.lan"],
        "investigation_log": ["Initial log"],
    }

    result = await enrich_ioc_node(state)

    assert "enrichment_results" in result
    enrichments = result["enrichment_results"]
    assert len(enrichments) >= 2  # 45.33.32.1 gets VT + AbuseIPDB; safe.internal.lan gets VT

    sources = {e["source"] for e in enrichments}
    assert any("AbuseIPDB" in s for s in sources)
    assert any("VirusTotal" in s for s in sources)
    assert all(e["status"] == "not_configured" for e in enrichments)
    assert all(e["reputation"] == "unknown" for e in enrichments)

    log_entry = result["investigation_log"][-1]
    assert "IOC Enrichment Agent" in log_entry
