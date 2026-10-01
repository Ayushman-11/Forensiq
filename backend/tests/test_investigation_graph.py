"""
End-to-end integration test for the upgraded LangGraph investigation pipeline.
Verifies the complete flow through:
  START -> extract_context -> enrich_iocs -> correlate_events -> map_mitre -> analyze_investigation -> END
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.agents.graph import investigation_graph


@pytest.mark.asyncio
async def test_full_investigation_graph_pipeline():
    initial_state = {
        "alert_data": {
            "_id": "test-pipeline-alert-001",
            "title": "Suspicious Encoded PowerShell Execution",
            "severity": "critical",
            "host": "DC-PRIMARY",
            "user": "SYSTEM",
            "rule_name": "Forensiq_Alert_Suspicious_PowerShell",
            "mitre_technique": "T1059.001",
            "event_code": "1",
            "raw_event": {
                "EventCode": "1",
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "CommandLine": "powershell.exe -Enc SQBFAFgAIAAoAE4AZQB3...",
                "SourceIp": "192.168.1.50",
                "DestinationIp": "185.220.101.5",
            },
        },
        "context": {},
        "extracted_iocs": [],
        "enrichment_results": [],
        "correlations": [],
        "investigation_log": ["Pipeline initiated"],
        "ai_analysis": None,
        "risk_assessment": {},
        "mitre_mappings": [],
        "timeline": [],
        "recommendation": None,
    }

    mock_correlations = [
        {
            "alert_id": "hist-alert-99",
            "title": "Earlier PowerShell Activity",
            "severity": "high",
            "status": "Investigated",
            "host": "DC-PRIMARY",
            "created_at": "2026-08-01T10:00:00Z",
            "matches": [{"type": "host", "value": "DC-PRIMARY"}],
        }
    ]

    with patch("app.agents.correlation_agent.get_db", new_callable=AsyncMock), \
         patch("app.agents.correlation_agent.correlate_alert", new_callable=AsyncMock) as mock_corr:
        mock_corr.return_value = mock_correlations

        final_state = await investigation_graph.ainvoke(initial_state)

        # 1. Context Agent output verification
        assert "context" in final_state
        assert final_state["context"].get("process_name") == "C:\\Windows\\System32\\powershell.exe"

        # 2. IOC Enrichment Agent output verification
        assert "extracted_iocs" in final_state
        assert "185.220.101.5" in final_state["extracted_iocs"]
        assert len(final_state["enrichment_results"]) >= 1

        # 3. Correlation Agent output verification (Step 1)
        assert "correlations" in final_state
        assert len(final_state["correlations"]) == 1
        assert final_state["correlations"][0]["alert_id"] == "hist-alert-99"

        # 4. MITRE ATT&CK Mapping Agent output verification (Step 2)
        assert "mitre_mappings" in final_state
        tech_ids = [m["technique_id"] for m in final_state["mitre_mappings"]]
        assert "T1059.001" in tech_ids

        # 5. Timeline Agent output verification (Step 3)
        assert "timeline" in final_state
        assert len(final_state["timeline"]) >= 2
        phases = [e["phase"] for e in final_state["timeline"]]
        assert any("Execution" in p for p in phases)

        # 6. Risk Assessment Agent output verification (Step 4)
        assert "risk_assessment" in final_state
        assert 0 <= final_state["risk_assessment"]["risk_score"] <= 100
        assert final_state["risk_assessment"]["priority"] in ("critical", "high", "medium", "low")

        # 7. Recommendation Agent output verification (Step 4)
        assert final_state["recommendation"] is not None
        assert "Actionable Steps" in final_state["recommendation"] or len(final_state["recommendation"]) > 10

        # 8. Investigation Log completeness
        log = final_state["investigation_log"]
        assert any("Context extraction" in entry for entry in log)
        assert any("IOC Enrichment" in entry for entry in log)
        assert any("Correlation Agent" in entry for entry in log)
        assert any("MITRE ATT&CK Agent" in entry for entry in log)
        assert any("Timeline Agent" in entry for entry in log)
        assert any("Risk" in entry for entry in log)
        assert any("Recommendation" in entry for entry in log)
