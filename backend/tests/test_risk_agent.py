"""
Unit tests for Risk Assessment Agent Node.
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.agents.risk_agent import assess_risk_node


@pytest.mark.asyncio
async def test_risk_agent_grok_llm_success():
    state = {
        "alert_data": {
            "_id": "risk-test-1",
            "title": "Cobalt Strike Beacon",
            "severity": "critical",
            "host": "DC-PRIMARY",
        },
        "context": {"dest_ip": "194.26.29.112"},
        "enrichment_results": [{"ioc": "194.26.29.112", "reputation": "malicious", "threat_score": 95}],
        "correlations": [{"alert_id": "c1", "host": "DC-PRIMARY"}],
        "mitre_mappings": [{"technique": "T1071.001", "name": "Web Protocols"}],
        "investigation_log": [],
    }

    mock_llm_json = """{
      "risk_score": 94,
      "confidence_score": 98,
      "priority": "critical",
      "reasoning": "High-confidence Cobalt Strike C2 beacon communication identified on critical domain controller.",
      "threat_summary": "Active C2 beacon connection from DC-PRIMARY to known malicious external IP.",
      "blast_radius": "domain_wide"
    }"""

    with patch("app.agents.risk_agent.query_grok_llm", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = mock_llm_json

        result = await assess_risk_node(state)
        risk = result["risk_assessment"]

        assert risk["risk_score"] == 94
        assert risk["priority"] == "critical"
        assert risk["confidence_score"] == 98
        assert risk["engine"] == "grok_llm"
        assert "Cobalt Strike" in risk["reasoning"]
        assert any("Grok AI Risk Agent" in log for log in result["investigation_log"])


@pytest.mark.asyncio
async def test_risk_agent_fallback_when_grok_uncredited():
    state = {
        "alert_data": {
            "_id": "risk-test-2",
            "title": "Failed Logins",
            "severity": "high",
            "host": "AUTH-01",
        },
        "context": {},
        "enrichment_results": [],
        "correlations": [],
        "mitre_mappings": [{"technique": "T1110.001", "name": "Brute Force"}],
        "investigation_log": [],
    }

    # Simulate Grok API returning None (e.g. 403 no credits)
    with patch("app.agents.risk_agent.query_grok_llm", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = None

        result = await assess_risk_node(state)
        risk = result["risk_assessment"]

        assert risk["risk_score"] >= 58
        assert risk["engine"] == "deterministic_fallback"
        assert any("Deterministic Heuristic Engine" in log for log in result["investigation_log"])
