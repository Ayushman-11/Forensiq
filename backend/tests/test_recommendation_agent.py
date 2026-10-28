"""
Unit tests for Investigation Recommendation Agent Node.
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.agents.recommendation_agent import generate_recommendations_node


@pytest.mark.asyncio
async def test_recommendation_agent_grok_llm_success():
    state = {
        "alert_data": {
            "_id": "rec-test-1",
            "title": "Encoded PowerShell",
            "host": "WKSTN-11",
            "severity": "critical",
        },
        "risk_assessment": {"risk_score": 92, "priority": "critical"},
        "mitre_mappings": [{"technique": "T1059.001"}],
        "enrichment_results": [{"ioc": "185.220.101.5", "reputation": "malicious"}],
        "correlations": [],
        "timeline": [],
        "investigation_log": [],
    }

    mock_llm_json = """{
      "recommendation": "Isolate workstation WKSTN-11 immediately to prevent lateral movement.",
      "checklist": [
        "Network-isolate endpoint WKSTN-11 using EDR agent",
        "Block destination IP 185.220.101.5 at perimeter gateway",
        "Dump and analyze PowerShell process memory"
      ],
      "containment_required": true
    }"""

    with patch("app.agents.recommendation_agent.query_grok_llm", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = mock_llm_json

        result = await generate_recommendations_node(state)
        rec = result["recommendation"]

        assert "Isolate workstation WKSTN-11" in rec
        assert "Network-isolate endpoint" in rec
        assert "Block destination IP" in rec
        assert any("Grok AI Recommendation Agent" in log for log in result["investigation_log"])


@pytest.mark.asyncio
async def test_recommendation_agent_deterministic_fallback():
    state = {
        "alert_data": {
            "_id": "rec-test-2",
            "title": "Registry Persistence",
            "host": "DEV-02",
            "severity": "high",
        },
        "risk_assessment": {"risk_score": 65, "priority": "high"},
        "mitre_mappings": [{"technique": "T1547.001"}],
        "enrichment_results": [],
        "correlations": [],
        "timeline": [],
        "investigation_log": [],
    }

    with patch("app.agents.recommendation_agent.query_grok_llm", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = None

        result = await generate_recommendations_node(state)
        rec = result["recommendation"]

        assert "CurrentVersion\\Run" in rec or "persistence" in rec.lower()
        assert any("Deterministic Engine" in log for log in result["investigation_log"])
