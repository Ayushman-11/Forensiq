from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import structlog
from mongomock_motor import AsyncMongoMockClient
from structlog.testing import capture_logs

from app.core.startup_checks import missing_integrations
from app.database.session import db_config
from app.main import app, lifespan


def _s(vt="", abuse="", xai=""):
    return SimpleNamespace(VT_API_KEY=vt, ABUSEIPDB_API_KEY=abuse, XAI_API_KEY=xai)


def test_everything_missing():
    assert missing_integrations(_s()) == {
        "threat_intel": ["VT_API_KEY", "ABUSEIPDB_API_KEY"],
        "llm": ["XAI_API_KEY"],
    }


def test_partial_and_whitespace_values():
    assert missing_integrations(_s(vt="k", abuse="  ", xai="x")) == {"threat_intel": ["ABUSEIPDB_API_KEY"]}


def test_all_configured_returns_empty():
    assert missing_integrations(_s("a", "b", "c")) == {}


async def _run_lifespan(monkeypatch, **keys):
    from app.core.config import settings
    for name, value in keys.items():
        monkeypatch.setattr(settings, name, value)
    client = AsyncMongoMockClient()

    async def fake_connect():
        db_config.client = client

    with patch("app.main.connect_to_mongo", new=fake_connect), \
         patch("app.main.AlertPoller.start", new=Mock()), \
         patch("app.main.setup_logging", new=Mock()), \
         patch("app.main.logger", structlog.get_logger()), \
         capture_logs() as logs:
        async with lifespan(app):
            pass
    db_config.client = None
    return logs


@pytest.mark.asyncio
async def test_lifespan_warns_when_keys_empty(monkeypatch):
    logs = await _run_lifespan(monkeypatch, VT_API_KEY="", ABUSEIPDB_API_KEY="", XAI_API_KEY="")
    ti = [e for e in logs if e["event"] == "threat_intel_not_configured"]
    llm = [e for e in logs if e["event"] == "llm_not_configured"]
    assert len(ti) == 1 and ti[0]["log_level"] == "warning"
    assert ti[0]["missing"] == ["VT_API_KEY", "ABUSEIPDB_API_KEY"]
    assert len(llm) == 1 and llm[0]["log_level"] == "warning"
    assert "deterministic rules" in llm[0]["message"]


@pytest.mark.asyncio
async def test_lifespan_silent_when_keys_configured(monkeypatch):
    logs = await _run_lifespan(monkeypatch, VT_API_KEY="v-secret", ABUSEIPDB_API_KEY="a-secret", XAI_API_KEY="x-secret")
    assert not [e for e in logs if e["event"] in ("threat_intel_not_configured", "llm_not_configured")]
    assert "secret" not in repr(logs)


@pytest.mark.asyncio
async def test_lifespan_lists_only_the_missing_threat_intel_key(monkeypatch):
    logs = await _run_lifespan(monkeypatch, VT_API_KEY="v", ABUSEIPDB_API_KEY="", XAI_API_KEY="x")
    ti = [e for e in logs if e["event"] == "threat_intel_not_configured"]
    assert ti[0]["missing"] == ["ABUSEIPDB_API_KEY"]
    assert not [e for e in logs if e["event"] == "llm_not_configured"]
