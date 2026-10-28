"""
Risk Assessment Agent Node for LangGraph.
Evaluates threat severity, IOC maliciousness, correlation breadth, and MITRE tactics
using the Grok AI LLM with prompt injection defense, structured evidence citation,
and deterministic heuristic fallback.
"""

from typing import Dict, Any, List, Optional, Set
import json
from app.core.config import settings
from app.core.logging import logger
from app.agents.state import AgentState
from app.agents.llm_client import query_grok_llm, extract_json_from_text, get_latest_query_metadata
from app.agents.prompt_guard import (
    build_guarded_prompt,
    SYSTEM_INJECTION_DEFENSE_PROMPT,
)


RISK_SYSTEM_PROMPT = f"""You are a Senior Principal SOC Analyst and Incident Response Lead.
Your objective is to evaluate security incidents, telemetry, threat intelligence, and correlation breadth.
Assess the threat severity and output a strictly valid JSON response with the following schema:
{{
  "risk_score": <int between 0 and 100>,
  "confidence_score": <int between 0 and 100>,
  "priority": "<critical|high|medium|low>",
  "reasoning": "<concise 2-3 sentence technical justification citing evidence IDs>",
  "threat_summary": "<concise 1-2 sentence executive summary of the attack>",
  "blast_radius": "<isolated_host|multi_host|domain_wide>",
  "cited_evidence_ids": ["<EVID-ID-1>", "<EVID-ID-2>"]
}}

{SYSTEM_INJECTION_DEFENSE_PROMPT}

Do not include any conversational filler or markdown code blocks outside of valid JSON.
"""


def _build_evidence_catalog(
    alert: dict,
    enrichments: list,
    correlations: list,
    mitre_mappings: list,
    context: dict,
) -> Dict[str, Any]:
    """Indexes all observational telemetry into uniquely identifiable evidence records."""
    catalog: Dict[str, Any] = {
        "EVID-ALERT": {
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "host": alert.get("host"),
            "user": alert.get("user"),
            "rule_name": alert.get("rule_name"),
            "event_code": alert.get("event_code"),
        }
    }

    if context:
        catalog["EVID-CONTEXT"] = {k: v for k, v in context.items() if v}

    for i, e in enumerate(enrichments, start=1):
        catalog[f"EVID-IOC-{i}"] = {
            "ioc": e.get("ioc"),
            "reputation": e.get("reputation"),
            "threat_score": e.get("threat_score"),
            "source": e.get("source"),
        }

    for i, c in enumerate(correlations, start=1):
        catalog[f"EVID-CORR-{i}"] = {
            "alert_id": c.get("alert_id"),
            "host": c.get("host"),
            "title": c.get("title"),
        }

    for i, m in enumerate(mitre_mappings, start=1):
        catalog[f"EVID-MITRE-{i}"] = {
            "technique": m.get("technique"),
            "name": m.get("name"),
            "tactic": m.get("tactic"),
        }

    return catalog


def _validate_evidence_citations(
    parsed: dict,
    valid_ids: Set[str],
    alert: dict,
) -> bool:
    """
    Validates that the LLM response cited legitimate evidence IDs from the catalog.
    Rejects hallucinations and empty citations per Section 2.3 requirement.
    """
    cited = parsed.get("cited_evidence_ids")
    if cited is not None:
        if not isinstance(cited, list) or len(cited) == 0:
            logger.warning("llm_risk_rejected_empty_citations")
            return False
        # Reject if zero cited IDs match known valid catalog IDs
        valid_citations = [eid for eid in cited if eid in valid_ids]
        if not valid_citations:
            logger.warning("llm_risk_rejected_hallucinated_citations", cited=cited)
            return False
        return True

    # Legacy/mock test compatibility: verify text contains references to host or alert title
    reasoning = str(parsed.get("reasoning", ""))
    summary = str(parsed.get("threat_summary", ""))
    combined = f"{reasoning} {summary}".lower()

    host = str(alert.get("host", "")).lower()
    title = str(alert.get("title", "")).lower()
    if (host and host in combined) or (title and title in combined) or any(eid.lower() in combined for eid in valid_ids):
        return True

    logger.warning("llm_risk_rejected_no_evidence_cited")
    return False


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
    answered = sum(1 for item in enrichments if item.get("status", "ok") == "ok")
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
        "confidence_score": min(99, max(30, 55 + answered * 5 + min(15, len(mitre_mappings) * 5))),
        "priority": priority,
        "reasoning": reasoning,
        "threat_summary": threat_summary,
        "blast_radius": blast_radius,
        "cited_evidence_ids": ["EVID-ALERT"],
        "engine": "deterministic_fallback",
    }


async def assess_risk_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Analyzes full alert context, IOC reputations, MITRE mappings,
    and correlations using Grok AI with prompt-injection defense and evidence citation.
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    enrichments = state.get("enrichment_results", [])
    correlations = state.get("correlations", [])
    mitre_mappings = state.get("mitre_mappings", [])
    current_log = state.get("investigation_log", [])

    alert_id = str(alert.get("_id", "unknown"))
    org_id = alert.get("org_id", "default")
    logger.info("risk_agent_start", alert_id=alert_id)

    # 1. Build structured evidence catalog
    catalog = _build_evidence_catalog(alert, enrichments, correlations, mitre_mappings, context)
    valid_evidence_ids = set(catalog.keys())

    # 2. Build injection-hardened prompt
    telemetry_summary = {
        "host": alert.get("host"),
        "user": alert.get("user"),
        "command_line": alert.get("command_line"),
        "dns_query": alert.get("dns_query"),
        "raw_logs": alert.get("raw_logs"),
    }
    user_prompt = build_guarded_prompt(
        telemetry=telemetry_summary,
        evidence_catalog=catalog,
        user_instruction="Analyze the security event telemetry and determine risk score, priority, and attack summary.",
    )

    # 3. Query LLM
    grok_response = await query_grok_llm(
        prompt=user_prompt,
        system_prompt=RISK_SYSTEM_PROMPT,
        response_json=True,
        org_id=org_id,
    )
    parsed = extract_json_from_text(grok_response) if grok_response else None

    # 4. Enforce evidence citation and reject answers that cite nothing
    is_valid_citation = _validate_evidence_citations(parsed, valid_evidence_ids, alert) if parsed else False

    llm_meta = get_latest_query_metadata()

    if parsed and is_valid_citation and isinstance(parsed.get("risk_score"), (int, float)):
        risk_score = max(0, min(100, int(parsed["risk_score"])))
        priority = str(parsed.get("priority", "medium")).lower()
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
            "cited_evidence_ids": parsed.get("cited_evidence_ids", ["EVID-ALERT"]),
            "engine": "grok_llm",
            "model": llm_meta.get("model", settings.XAI_MODEL),
            "prompt_version": settings.LLM_PROMPT_VERSION,
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
        "llm_metadata": llm_meta,
    }
