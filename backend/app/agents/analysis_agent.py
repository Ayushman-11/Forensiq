"""Transparent, deterministic investigation decision layer.

This is deliberately not presented as an LLM verdict. It turns the evidence
already collected by the MVP pipeline into a reproducible risk assessment,
timeline, and analyst next step. A model-backed agent can replace this node
later without changing the state contract.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from app.agents.state import AgentState


def analyze_investigation_node(state: AgentState) -> Dict[str, Any]:
    alert = state.get("alert_data", {})
    enrichments = state.get("enrichment_results", [])
    severity = str(alert.get("severity", "medium")).lower()
    severity_score = {"critical": 75, "high": 58, "medium": 38, "low": 18}.get(severity, 25)
    malicious = sum(1 for item in enrichments if item.get("reputation") == "malicious")
    suspicious = sum(1 for item in enrichments if item.get("reputation") == "suspicious")
    risk_score = min(100, severity_score + malicious * 15 + suspicious * 8)
    priority = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 35 else "low"

    technique = alert.get("mitre_technique")
    tactic = alert.get("mitre_tactic")
    mitre_mappings = ([{"technique": technique, "tactic": tactic}] if technique else [])

    timestamp = alert.get("created_at") or datetime.now(timezone.utc).isoformat()
    timeline = [{
        "timestamp": timestamp,
        "event_type": alert.get("alert_type", "Detection"),
        "description": alert.get("title", "Security alert detected"),
        "source": alert.get("source_siem", "splunk"),
    }]

    if malicious:
        recommendation = "Contain the affected host and validate the malicious IOC before closing the alert."
    elif suspicious:
        recommendation = "Review the suspicious IOC, related process activity, and neighboring events before disposition."
    elif risk_score >= 60:
        recommendation = "Review the alert context and correlate activity on the affected host before disposition."
    else:
        recommendation = "Confirm the detection context and close as benign only when the evidence supports it."

    log = state.get("investigation_log", []) + [
        f"Decision layer complete: {priority} priority, risk {risk_score}/100"
    ]
    return {
        "risk_assessment": {
            "risk_score": risk_score,
            "priority": priority,
            "confidence_score": min(99, max(25, 55 + len(enrichments) * 5)),
        },
        "mitre_mappings": mitre_mappings,
        "timeline": timeline,
        "recommendation": recommendation,
        "investigation_log": log,
    }
