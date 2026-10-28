"""
Unit tests for Correlation Agent Node in LangGraph.
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.agents.correlation_agent import correlate_events_node


@pytest.mark.asyncio
async def test_correlate_events_node_success():
    state = {
        "alert_data": {
            "_id": "alert-test-c1",
            "host": "WKSTN-01",
            "user": "CORP\\alice",
            "extracted_iocs": ["192.168.1.50"],
        },
        "context": {
            "source_ip": "10.0.0.99",
            "process_name": "powershell.exe",
        },
        "extracted_iocs": ["185.220.101.5"],
        "investigation_log": ["Initial log entry"],
    }
    
    mock_correlations = [
        {
            "alert_id": "alert-hist-1",
            "title": "Historical Alert",
            "severity": "high",
            "status": "Investigated",
            "host": "WKSTN-01",
            "created_at": "2026-08-01T12:00:00Z",
            "matches": [{"type": "host", "value": "WKSTN-01"}],
        }
    ]
    
    with patch("app.agents.correlation_agent.get_db", new_callable=AsyncMock) as mock_get_db, \
         patch("app.agents.correlation_agent.correlate_alert", new_callable=AsyncMock) as mock_correlate:
        mock_get_db.return_value = AsyncMock()
        mock_correlate.return_value = mock_correlations
        
        result = await correlate_events_node(state)
        
        assert "correlations" in result
        assert len(result["correlations"]) == 1
        assert result["correlations"][0]["alert_id"] == "alert-hist-1"
        assert len(result["investigation_log"]) == 2
        assert "Correlation Agent" in result["investigation_log"][-1]
        
        # Verify merged alert passed to correlate_alert
        call_args = mock_correlate.call_args[0]
        passed_alert = call_args[1]
        assert passed_alert["process_name"] == "powershell.exe"
        assert "185.220.101.5" in passed_alert["extracted_iocs"]


@pytest.mark.asyncio
async def test_correlate_events_node_no_matches():
    state = {
        "alert_data": {"_id": "alert-test-c2", "host": "ISOLATED-HOST"},
        "context": {},
        "extracted_iocs": [],
        "investigation_log": [],
    }
    
    with patch("app.agents.correlation_agent.get_db", new_callable=AsyncMock), \
         patch("app.agents.correlation_agent.correlate_alert", new_callable=AsyncMock) as mock_correlate:
        mock_correlate.return_value = []
        
        result = await correlate_events_node(state)
        
        assert result["correlations"] == []
        assert any("no historical alert correlations found" in log for log in result["investigation_log"])


@pytest.mark.asyncio
async def test_correlate_events_node_error_handling():
    state = {
        "alert_data": {"_id": "alert-test-c3"},
        "context": {},
        "extracted_iocs": [],
        "investigation_log": [],
    }
    
    with patch("app.agents.correlation_agent.get_db", side_effect=Exception("DB Connection Refused")):
        result = await correlate_events_node(state)
        
        # Should not raise; graceful fallback
        assert result["correlations"] == []
        assert any("could not complete" in log for log in result["investigation_log"])


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", ["get_db", "correlate_alert"])
async def test_correlate_events_node_failure_does_not_leak_exception_text(failing):
    secret = "mongodb://user:s3cr3t@internal-host:27017 refused"
    state = {"alert_data": {"_id": "a1"}, "context": {}, "extracted_iocs": [], "investigation_log": ["start"]}
    boom = AsyncMock(side_effect=RuntimeError(secret))
    with patch("app.agents.correlation_agent.get_db", boom if failing == "get_db" else AsyncMock()), \
         patch("app.agents.correlation_agent.correlate_alert", boom if failing == "correlate_alert" else AsyncMock()):
        result = await correlate_events_node(state)
    assert result["correlations"] == []
    assert result["investigation_log"] == ["start", "Correlation Agent could not complete (see server logs)"]
    assert "s3cr3t" not in " ".join(result["investigation_log"])
