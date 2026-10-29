"""
Unit tests for Timeline Agent Node in LangGraph.
"""

import pytest
from app.agents.timeline_agent import build_timeline_node, PHASE_EXECUTION, PHASE_C2, PHASE_PERSISTENCE


def test_build_timeline_from_alert_and_context():
    state = {
        "alert_data": {
            "_id": "alert-tl-001",
            "title": "Suspicious PowerShell Execution",
            "severity": "critical",
            "host": "WKSTN-FIN-01",
            "created_at": "2026-08-10T14:30:00Z",
            "alert_type": "Command and Scripting Interpreter",
        },
        "context": {
            "parent_process": "C:\\Windows\\explorer.exe",
            "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -Enc SQBFAFgAIAA...",
            "dest_ip": "185.220.101.5",
            "dest_port": "443",
        },
        "correlations": [
            {
                "alert_id": "hist-tl-002",
                "title": "Earlier Network Reconnaissance",
                "severity": "medium",
                "host": "WKSTN-FIN-01",
                "created_at": "2026-08-10T14:15:00Z",
                "matches": [{"type": "host", "value": "WKSTN-FIN-01"}],
            }
        ],
        "enrichment_results": [
            {
                "ioc": "185.220.101.5",
                "ioc_type": "ip",
                "reputation": "malicious",
                "threat_score": 90,
                "source": "VirusTotal",
            }
        ],
        "mitre_mappings": [{"technique": "T1059.001", "tactic": "Execution"}],
        "investigation_log": ["Init"],
    }

    result = build_timeline_node(state)
    timeline = result["timeline"]

    assert len(timeline) >= 4

    # Verify chronological ordering
    timestamps = [e["timestamp"] for e in timeline]
    assert timestamps == sorted(timestamps)

    # Verify that the earlier correlated alert appears first
    assert "Earlier Network Reconnaissance" in timeline[0]["description"]

    # Verify distinct phases
    phases = [e["phase"] for e in timeline]
    assert any("Execution" in p for p in phases)
    assert any("Command and Control" in p for p in phases)

    # Verify logging
    assert any("Timeline Agent" in log for log in result["investigation_log"])
