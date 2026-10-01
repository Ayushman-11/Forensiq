"""
Risk Assessment Agent Node for LangGraph.
Evaluates threat severity, IOC maliciousness, correlation breadth, and MITRE tactics
using the Grok AI LLM (with deterministic heuristic fallback).
"""

from typing import Dict, Any, List, Optional
import json
from app.core.logging import logger
from app.agents.state import AgentState
from app.agents.llm_client import query_grok_llm, extract_json_from_text


RISK_SYSTEM_PROMPT = """You are a Senior Principal SOC Analyst and Incident Response Lead.
Your objective is to evaluate security incidents, telemetry, threat intelligence, and correlation breadth.
Assess the threat severity and output a strictly valid JSON response with the following schema:
{
  "risk_score": <int between 0 and 100>,
  "confidence_score": <int between 0 and 100>,
  "priority": "<critical|high|medium|low>",
  "reasoning": "<concise 2-3 sentence technical justification>",
  "threat_summary": "<concise 1-2 sentence executive summary of the attack>",
  "blast_radius": "<isolated_host|multi_host|domain_wide>"
}
Do not include any conversational filler or markdown code blocks outside of valid JSON.
"""


def _deterministic_risk_assessment(
    alert: dict,
    enrichments: list,
    correlations: list,
    mitre_mappings: list,
) -> Dict[str, Any]:
    """Calibrated rule engine for when LLM is unavailable or uncredited."""
    severity = str(alert.get("severity", "medium")).lower()
    severity_score = {"critical": 75, "high": 58, "medium": 38, "low": 18}.get(severity, 25)
    
    malicious = sum(1 for item in enrichments if item.get("reputation") == "malicious")
    suspicious = sum(1 for item in enrichments if item.get("reputation") == "suspicious")
    correlation_bump = min(20, len(correlations) * 5)
    mitre_bump = min(10, len(mitre_mappings) * 3)

    risk_score = min(100, severity_score + malicious * 15 + suspicious * 8 + correlation_bump + mitre_bump)
    priority = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 35 else "low"
    
    correlated_hosts = {c.get("host") for c in correlations if c.get("host")}
    blast_radius = "multi_host" if len(correlated_hosts) > 1 else "isolated_host"

    reasoning = (
        f"Evaluated alert severity ({severity.upper()}), {malicious} malicious and {suspicious} suspicious IOCs, "
        f"{len(correlations)} correlated historical detections, and {len(mitre_mappings)} MITRE technique mappings."
    )
    threat_summary = f"{alert.get('title', 'Detection')} observed on host {alert.get('host', 'unknown')} with risk score {risk_score}/100."

    return {
        "risk_score": risk_score,
        "confidence_score": min(99, max(30, 55 + len(enrichments) * 5 + min(15, len(mitre_mappings) * 5))),
        "priority": priority,
        "reasoning": reasoning,
        "threat_summary": threat_summary,
        "blast_radius": blast_radius,
        "engine": "deterministic_fallback",
    }


async def assess_risk_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Analyzes full alert context, IOC reputations, MITRE mappings,
    and correlations using Grok AI (or deterministic engine if uncredited).
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    enrichments = state.get("enrichment_results", [])
    correlations = state.get("correlations", [])
    mitre_mappings = state.get("mitre_mappings", [])
    current_log = state.get("investigation_log", [])

    alert_id = str(alert.get("_id", "unknown"))
    logger.info("risk_agent_start", alert_id=alert_id)

    # Prepare structured summary for Grok
    llm_input = {
        "alert": {
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "host": alert.get("host"),
            "user": alert.get("user"),
            "rule_name": alert.get("rule_name"),
        },
        "telemetry_context": context,
        "threat_intelligence": [
            {"ioc": e.get("ioc"), "reputation": e.get("reputation"), "threat_score": e.get("threat_score")}
            for e in enrichments
        ],
        "correlated_alerts_count": len(correlations),
        "correlated_hosts": list({c.get("host") for c in correlations if c.get("host")}),
        "mitre_techniques": [
            {"technique": m.get("technique"), "name": m.get("name"), "tactic": m.get("tactic")}
            for m in mitre_mappings
        ],
    }

    user_prompt = f"Analyze the following security event telemetry and determine risk:\n{json.dumps(llm_input, indent=2)}"

    # Attempt query to Grok AI
    grok_response = await query_grok_llm(user_prompt, RISK_SYSTEM_PROMPT, response_json=True)
    parsed = extract_json_from_text(grok_response) if grok_response else None

    if parsed and isinstance(parsed.get("risk_score"), (int, float)):
        risk_score = max(0, min(100, int(parsed["risk_score"])))
        priority = parsed.get("priority", "medium").lower()
        if priority not in ("critical", "high", "medium", "low"):
            priority = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium"
        confidence = max(0, min(100, int(parsed.get("confidence_score", 85))))

        risk_assessment = {
            "risk_score": risk_score,
            "confidence_score": confidence,
            "priority": priority,
            "reasoning": parsed.get("reasoning", "Assessed by Grok AI."),
            "threat_summary": parsed.get("threat_summary", ""),
            "blast_radius": parsed.get("blast_radius", "isolated_host"),
            "engine": "grok_llm",
        }
        log_msg = f"Grok AI Risk Agent: evaluated risk score {risk_score}/100 ({priority} priority) with {confidence}% confidence via Grok"
    else:
        # Graceful deterministic fallback
        risk_assessment = _deterministic_risk_assessment(alert, enrichments, correlations, mitre_mappings)
        log_msg = (
            f"Risk Assessment Agent: calculated calibrated risk {risk_assessment['risk_score']}/100 "
            f"({risk_assessment['priority']} priority) [Deterministic Heuristic Engine]"
        )

    logger.info("risk_agent_complete", alert_id=alert_id, risk_score=risk_assessment["risk_score"])
    new_log = current_log + [log_msg]

    return {
        "risk_assessment": risk_assessment,
        "ai_analysis": risk_assessment.get("threat_summary"),
        "investigation_log": new_log,
    }
