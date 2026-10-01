"""
Investigation Recommendation Agent Node for LangGraph.
Synthesizes full investigation findings, risk assessments, and ATT&CK mappings
into an actionable incident response checklist using Grok AI (with deterministic fallback).
"""

from typing import Dict, Any, List, Optional
import json
from app.core.logging import logger
from app.agents.state import AgentState
from app.agents.llm_client import query_grok_llm, extract_json_from_text


REC_SYSTEM_PROMPT = """You are a Principal Incident Response Commander.
Based on the security alert evidence, risk assessment, MITRE tactics, and attack timeline,
generate concrete, actionable next steps for the SOC team.
Output a strictly valid JSON response with the following schema:
{
  "recommendation": "<concise 1-2 sentence primary action directive>",
  "checklist": [
    "<action 1: immediate containment/isolation>",
    "<action 2: eradication/process termination/firewall block>",
    "<action 3: forensic verification/hunting>"
  ],
  "containment_required": <true|false>
}
Do not include any conversational text or markdown code blocks outside of valid JSON.
"""


def _deterministic_recommendation(
    alert: dict,
    enrichments: list,
    correlations: list,
    mitre_mappings: list,
    risk_assessment: dict,
) -> Dict[str, Any]:
    """Generates defensive checklists using rule-based heuristics."""
    risk_score = risk_assessment.get("risk_score", 50)
    host = alert.get("host") or "target host"
    malicious = [e for e in enrichments if e.get("reputation") == "malicious"]
    correlated_hosts = {c.get("host") for c in correlations if c.get("host")}
    techniques = [m.get("technique") for m in mitre_mappings]

    checklist: List[str] = []
    containment_required = False

    if malicious and len(correlated_hosts) > 1:
        containment_required = True
        checklist.append(f"Immediately isolate host '{host}' and peer systems ({', '.join(list(correlated_hosts)[:3])}) from the local network.")
        for m in malicious:
            checklist.append(f"Block confirmed malicious {m.get('ioc_type', 'indicator')} '{m.get('ioc')}' on perimeter firewalls and EDR.")
        checklist.append("Inspect Active Directory authentication logs for unusual Kerberos tickets or lateral movement.")
        directive = f"Active multi-host threat detected! Immediately isolate host '{host}' and peer endpoints, and block malicious indicators."

    elif malicious:
        containment_required = True
        checklist.append(f"Isolate endpoint '{host}' and terminate associated parent/child processes.")
        for m in malicious:
            checklist.append(f"Submit IOC '{m.get('ioc')}' to blocklists and revoke active sessions.")
        checklist.append("Perform full forensic triage and memory dump on the endpoint before remediation.")
        directive = f"Confirmed malicious indicators detected. Contain host '{host}', terminate suspicious processes, and validate IOCs."

    elif "T1547.001" in techniques or "T1053.005" in techniques:
        checklist.append(f"Inspect Windows Registry under CurrentVersion\\Run and scheduled tasks on '{host}'.")
        checklist.append("Identify and remove unauthorized autostart binaries from AppData or Temp directories.")
        checklist.append("Review persistence artifacts and correlate execution timestamps against user logon sessions.")
        directive = f"Potential persistence mechanism identified on '{host}'. Inspect registry autostart keys and scheduled tasks."

    elif "T1110.001" in techniques or "4625" in str(alert.get("event_code", "")):
        checklist.append(f"Review target account '{alert.get('user', 'affected account')}' for signs of successful compromise (EventCode 4624).")
        checklist.append("Force password reset and terminate all active sessions if brute force was successful.")
        checklist.append(f"Block the offending source IP address ({alert.get('source_ip', 'external')}) on the authentication gateway.")
        directive = f"High-volume authentication failure detected. Verify account status and enforce password rotation if needed."

    elif risk_score >= 60:
        checklist.append(f"Inspect host '{host}' process telemetry and open network sockets.")
        checklist.append("Correlate neighboring events 15 minutes before and after the alert trigger.")
        checklist.append("Verify whether the command line execution is part of authorized IT administrative tasks.")
        directive = f"Elevated threat score on '{host}'. Review alert context and correlate activity before disposition."

    else:
        checklist.append("Confirm the detection context against normal host baseline.")
        checklist.append("Verify with the end user if the activity was expected and authorized.")
        checklist.append("Close as benign or false positive only when telemetry supports it.")
        directive = "Confirm the detection context and close as benign only when the evidence supports it."

    return {
        "recommendation": directive,
        "checklist": checklist,
        "containment_required": containment_required,
        "engine": "deterministic_fallback",
    }


async def generate_recommendations_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Produces specific, actionable investigation and containment recommendations
    using Grok AI (with deterministic fallback).
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    enrichments = state.get("enrichment_results", [])
    correlations = state.get("correlations", [])
    mitre_mappings = state.get("mitre_mappings", [])
    timeline = state.get("timeline", [])
    risk_assessment = state.get("risk_assessment", {})
    current_log = state.get("investigation_log", [])

    alert_id = str(alert.get("_id", "unknown"))
    logger.info("recommendation_agent_start", alert_id=alert_id)

    llm_input = {
        "alert": {
            "title": alert.get("title"),
            "host": alert.get("host"),
            "user": alert.get("user"),
            "severity": alert.get("severity"),
        },
        "risk_assessment": risk_assessment,
        "mitre_techniques": [m.get("technique") for m in mitre_mappings],
        "malicious_iocs": [e.get("ioc") for e in enrichments if e.get("reputation") in ("malicious", "suspicious")],
        "correlated_alerts_count": len(correlations),
        "timeline_events_count": len(timeline),
    }

    user_prompt = f"Generate actionable SOC recommendations for this investigated alert:\n{json.dumps(llm_input, indent=2)}"

    # Attempt query to Grok AI
    grok_response = await query_grok_llm(user_prompt, REC_SYSTEM_PROMPT, response_json=True)
    parsed = extract_json_from_text(grok_response) if grok_response else None

    if parsed and isinstance(parsed.get("recommendation"), str):
        directive = parsed["recommendation"]
        checklist = parsed.get("checklist", [])
        if checklist and isinstance(checklist, list):
            formatted_rec = f"{directive}\n\nActionable Steps:\n" + "\n".join(f"• {item}" for item in checklist)
        else:
            formatted_rec = directive
        log_msg = f"Grok AI Recommendation Agent: generated response checklist with {len(checklist)} step(s) via Grok"
    else:
        # Fallback to deterministic checklist
        rec_data = _deterministic_recommendation(alert, enrichments, correlations, mitre_mappings, risk_assessment)
        directive = rec_data["recommendation"]
        checklist = rec_data["checklist"]
        formatted_rec = f"{directive}\n\nActionable Steps:\n" + "\n".join(f"• {item}" for item in checklist)
        log_msg = f"Recommendation Agent: generated response checklist with {len(checklist)} step(s) [Deterministic Engine]"

    logger.info("recommendation_agent_complete", alert_id=alert_id)
    new_log = current_log + [log_msg]

    return {
        "recommendation": formatted_rec,
        "investigation_log": new_log,
    }
