"""
Risk Assessment Agent Node for LangGraph.
Evaluates threat severity, asset criticality, indicator confidence, and rarity
with an explainable 'why this score' breakdown.
"""

from typing import Dict, Any, List, Optional
import json
from app.core.logging import logger
from app.agents.state import AgentState
from app.agents.llm_client import query_grok_llm, extract_json_from_text


def calculate_calibrated_risk_score(
    alert: dict,
    enrichments: list,
    correlations: list,
    mitre_mappings: list,
) -> Dict[str, Any]:
    """
    Computes an unsaturated, explainable risk score (0-100) based on:
    1. Base Severity (Critical=45, High=30, Medium=15, Low=5)
    2. Asset Criticality (Domain Controllers, Servers vs Workstations)
    3. IOC Confidence & Maliciousness
    4. MITRE Technique Impact & Correlation Breadth
    """
    breakdown = {}
    
    # 1. Base Severity Contribution (Max 45)
    severity = str(alert.get("severity", "medium")).lower()
    base_points = {"critical": 45, "high": 30, "medium": 15, "low": 5}.get(severity, 15)
    breakdown["base_severity"] = {"points": base_points, "factor": severity.upper()}

    # 2. Asset Criticality Contribution (Max 20)
    host = str(alert.get("host") or "").lower()
    user = str(alert.get("user") or "").lower()
    asset_points = 5
    asset_desc = "Standard Workstation / User"
    if any(dc_kw in host for dc_kw in ("dc", "domain", "srv", "server", "prod", "vault", "corp")):
        asset_points = 20
        asset_desc = "Critical Server / Domain Controller"
    elif any(adm in user for adm in ("admin", "root", "system")):
        asset_points = 15
        asset_desc = "Privileged User Account"
    breakdown["asset_criticality"] = {"points": asset_points, "factor": asset_desc}

    # 3. IOC Maliciousness & Confidence (Max 20)
    malicious = sum(1 for item in enrichments if item.get("reputation") == "malicious")
    suspicious = sum(1 for item in enrichments if item.get("reputation") == "suspicious")
    ioc_points = min(20, (malicious * 10) + (suspicious * 5))
    breakdown["indicator_reputation"] = {
        "points": ioc_points,
        "factor": f"{malicious} malicious, {suspicious} suspicious IOCs",
    }

    # 4. MITRE Technique & Attack Phase Rarity (Max 15)
    # Credential Dumping, Lateral Movement, or Persistence get higher weight
    critical_tactics = {"Credential Access", "Lateral Movement", "Defense Evasion"}
    tactic_hits = sum(1 for m in mitre_mappings if m.get("tactic") in critical_tactics)
    mitre_points = min(15, (tactic_hits * 5) + min(5, len(mitre_mappings) * 2))
    breakdown["tactics_breadth"] = {
        "points": mitre_points,
        "factor": f"{len(mitre_mappings)} ATT&CK mappings ({tactic_hits} high-impact tactics)",
    }
    answered = sum(1 for item in enrichments if item.get("status", "ok") == "ok")
    correlation_bump = min(20, len(correlations) * 5)
    mitre_bump = min(10, len(mitre_mappings) * 3)

    # Total Sum
    raw_score = base_points + asset_points + ioc_points + mitre_points
    # Add correlation bump (Max 10)
    corr_points = min(10, len(correlations) * 2)
    if corr_points:
        breakdown["historical_correlations"] = {
            "points": corr_points,
            "factor": f"{len(correlations)} correlated alerts in time window",
        }
    
    final_score = min(99, max(5, raw_score + corr_points))
    priority = "critical" if final_score >= 80 else "high" if final_score >= 60 else "medium" if final_score >= 35 else "low"

    blast_radius = "domain_wide" if asset_points >= 20 and len(correlations) > 3 else "multi_host" if len(correlations) > 1 else "isolated_host"

    return {
        "risk_score": final_score,
        "confidence_score": min(98, max(40, 50 + (len(enrichments) * 8) + (len(mitre_mappings) * 5))),
        "priority": priority,
        "score_breakdown": breakdown,
        "blast_radius": blast_radius,
        "threat_summary": f"Incident on {host or 'unknown'} scored at {final_score}/100 ({priority.upper()}).",
        "reasoning": f"Score composed of base severity ({base_points}pts), asset impact ({asset_points}pts), IOC findings ({ioc_points}pts), and ATT&CK scope ({mitre_points}pts).",
    }


async def assess_risk_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Analyzes full alert context, IOC reputations, MITRE mappings,
    and correlations to produce calibrated, unsaturated risk scores.
    """
    alert = state.get("alert_data", {})
    enrichments = state.get("enrichment_results", [])
    correlations = state.get("correlations", [])
    mitre_mappings = state.get("mitre_mappings", [])
    current_log = state.get("investigation_log", [])

    alert_id = str(alert.get("_id", "unknown"))
    logger.info("risk_agent_start", alert_id=alert_id)

    assessment = calculate_calibrated_risk_score(alert, enrichments, correlations, mitre_mappings)

    log_msg = (
        f"Risk Agent: calibrated risk score {assessment['risk_score']}/100 ({assessment['priority'].upper()}) "
        f"- {assessment['reasoning']}"
    )
    logger.info("risk_agent_complete", alert_id=alert_id, risk_score=assessment["risk_score"])

    return {
        "risk_assessment": assessment,
        "investigation_log": current_log + [log_msg],
    }
