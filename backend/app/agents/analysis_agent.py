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
    correlations = state.get("correlations", [])
    mitre_mappings = state.get("mitre_mappings") or []
    
    # Fallback for mitre_mappings if not present in state
    if not mitre_mappings:
        technique = alert.get("mitre_technique")
        tactic = alert.get("mitre_tactic")
        mitre_mappings = ([{"technique": technique, "tactic": tactic}] if technique else [])

    severity = str(alert.get("severity", "medium")).lower()
    severity_score = {"critical": 75, "high": 58, "medium": 38, "low": 18}.get(severity, 25)
    malicious = sum(1 for item in enrichments if item.get("reputation") == "malicious")
    suspicious = sum(1 for item in enrichments if item.get("reputation") == "suspicious")
    
    # Factor in correlation breadth
    correlation_bump = min(20, len(correlations) * 5)
    risk_score = min(100, severity_score + malicious * 15 + suspicious * 8 + correlation_bump)
    priority = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 35 else "low"

    timestamp = alert.get("created_at") or datetime.now(timezone.utc).isoformat()
    timeline = [{
        "timestamp": timestamp,
        "event_type": alert.get("alert_type", "Detection"),
        "description": alert.get("title", "Security alert detected"),
        "source": alert.get("source_siem", "splunk"),
    }]

    correlated_hosts = {c.get("host") for c in correlations if c.get("host")}
    host_label = alert.get("host") or "target host"

    if malicious and len(correlated_hosts) > 1:
        recommendation = (
            f"Active multi-host campaign detected! Malicious IOC observed across {len(correlated_hosts)} systems. "
            f"Immediately isolate host '{host_label}' and peer endpoints, and block the malicious indicator at perimeter firewalls."
        )
    elif malicious:
        recommendation = (
            f"Confirmed malicious indicators detected. Contain host '{host_label}', "
            f"terminate suspicious child processes, and validate the malicious IOC before closing the alert."
        )
    elif len(correlations) >= 2:
        recommendation = (
            f"High volume of correlated activity ({len(correlations)} related detections). "
            f"Investigate potential lateral movement and account compromise across affected systems."
        )
    elif suspicious:
        recommendation = "Review the suspicious IOC, related process activity, and neighboring events before disposition."
    elif risk_score >= 60:
        recommendation = f"Elevated threat score on '{host_label}'. Review alert context and correlate activity before disposition."
    else:
        recommendation = "Confirm the detection context and close as benign only when the evidence supports it."

    log = state.get("investigation_log", []) + [
        f"Decision layer complete: {priority} priority, risk {risk_score}/100"
    ]
    return {
        "risk_assessment": {
            "risk_score": risk_score,
            "priority": priority,
            "confidence_score": min(99, max(25, 55 + len(enrichments) * 5 + min(15, len(mitre_mappings) * 5))),
        },
        "mitre_mappings": mitre_mappings,
        "timeline": timeline,
        "recommendation": recommendation,
        "investigation_log": log,
    }
