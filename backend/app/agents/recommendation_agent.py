"""
Investigation Recommendation Agent Node for LangGraph.
Synthesizes full investigation findings, risk assessments, and ATT&CK mappings
into an actionable incident response checklist using Grok AI (with deterministic fallback).
Enforces:
1. Containment advice is always explicitly "suggested" and requires human approval.
2. Every recommendation cites evidence from the alert or threat intelligence.
3. Prompt injection defanging for untrusted telemetry.
"""

from functools import lru_cache
from typing import Dict, Any, List, Optional, Set
import json
from app.core.config import settings
from app.core.logging import logger
from app.normalization.noise import NoiseFilter
from app.agents.state import AgentState
from app.agents.llm_client import query_grok_llm, extract_json_from_text, get_latest_query_metadata
from app.agents.prompt_guard import (
    build_guarded_prompt,
    SYSTEM_INJECTION_DEFENSE_PROMPT,
)


REC_SYSTEM_PROMPT = f"""You are a Principal Incident Response Commander.
Based on the security alert evidence, risk assessment, MITRE tactics, and attack timeline,
generate concrete, actionable next steps for the SOC team.
Output a strictly valid JSON response with the following schema:
{{
  "recommendation": "<concise 1-2 sentence primary action directive>",
  "containment_advice": "suggested",
  "checklist": [
    "<action 1: immediate suggested containment/isolation (requires human approval)>",
    "<action 2: eradication/process termination/firewall block>",
    "<action 3: forensic verification/hunting>"
  ],
  "containment_required": <true|false>,
  "cited_evidence_ids": ["<EVID-ID-1>", "<EVID-ID-2>"]
}}

CRITICAL POLICY:
- Containment advice is ALWAYS strictly 'suggested'. All containment actions require explicit human approval.
- Cite the evidence IDs that justify your recommendations.

{SYSTEM_INJECTION_DEFENSE_PROMPT}

Do not include any conversational text or markdown code blocks outside of valid JSON.
"""


@lru_cache(maxsize=1)
def _noise_policy() -> NoiseFilter:
    return NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH)


async def _tenant_noise_policy(org_id: str) -> NoiseFilter:
    """The alert's own tenant policy; the platform policy when the tenant has none or the database is unreachable."""
    try:
        from app.database.session import get_db
        from app.services.tenants import noise_filter, resolve_config

        return noise_filter(await resolve_config(await get_db(), org_id))
    except Exception as exc:
        logger.warning("tenant_noise_policy_unavailable", org_id=org_id, error=str(exc))
        return _noise_policy()


def _build_evidence_catalog(
    alert: dict,
    enrichments: list,
    correlations: list,
    mitre_mappings: list,
) -> Dict[str, Any]:
    """Builds indexed catalog of evidence items for citation."""
    catalog: Dict[str, Any] = {
        "EVID-ALERT": {
            "title": alert.get("title"),
            "host": alert.get("host"),
            "user": alert.get("user"),
            "severity": alert.get("severity"),
        }
    }
    for i, e in enumerate(enrichments, start=1):
        catalog[f"EVID-IOC-{i}"] = {
            "ioc": e.get("ioc"),
            "reputation": e.get("reputation"),
            "source": e.get("source"),
        }
    for i, m in enumerate(mitre_mappings, start=1):
        catalog[f"EVID-MITRE-{i}"] = {
            "technique": m.get("technique"),
            "name": m.get("name"),
        }
    return catalog


def _validate_rec_citations(
    parsed: dict,
    valid_ids: Set[str],
    alert: dict,
) -> bool:
    """Validates citations in recommendation response."""
    cited = parsed.get("cited_evidence_ids")
    if cited is not None:
        if not isinstance(cited, list) or len(cited) == 0:
            logger.warning("llm_rec_rejected_empty_citations")
            return False
        valid_citations = [eid for eid in cited if eid in valid_ids]
        if not valid_citations:
            logger.warning("llm_rec_rejected_hallucinated_citations", cited=cited)
            return False
        return True

    # Legacy mock compatibility: check if alert or host or IOC was mentioned in recommendation or checklist
    text = (parsed.get("recommendation", "") + " " + " ".join(parsed.get("checklist", []))).lower()
    host = str(alert.get("host", "")).lower()
    title = str(alert.get("title", "")).lower()
    if (host and host in text) or (title and title in text) or any(eid.lower() in text for eid in valid_ids):
        return True

    logger.warning("llm_rec_rejected_no_evidence_cited")
    return False


def _malicious_by_ioc(enrichments: list) -> Dict[str, Dict[str, Any]]:
    """Group malicious verdicts per IOC, keeping the distinct feeds that agree."""
    grouped: Dict[str, Dict[str, Any]] = {}
    for e in enrichments:
        if e.get("reputation") != "malicious" or e.get("status", "ok") != "ok":
            continue
        entry = grouped.setdefault(e.get("ioc"), {"ioc": e.get("ioc"), "ioc_type": e.get("ioc_type", "indicator"), "sources": set()})
        entry["sources"].add(e.get("source"))
    return grouped


def _block_step(entry: Dict[str, Any], noise: NoiseFilter) -> str:
    ioc, ioc_type = entry["ioc"], entry["ioc_type"]
    sources = ", ".join(sorted(s for s in entry["sources"] if s))
    if ioc_type == "domain" and noise.is_shared_hosting(ioc):
        return (f"'{ioc}' is shared hosting flagged by {sources}: do not block the domain. "
                f"Pull proxy/DNS logs for the exact URLs fetched and block those URLs only.")
    if len(entry["sources"]) >= 2:
        return f"Suggested (Requires human approval): Block confirmed malicious {ioc_type} '{ioc}' (corroborated by {sources}) on firewalls and EDR."
    return f"Validate {ioc_type} '{ioc}' (flagged only by {sources}) against a second source before blocking it."


def _deterministic_recommendation(
    alert: dict,
    enrichments: list,
    correlations: list,
    mitre_mappings: list,
    risk_assessment: dict,
    noise: Optional[NoiseFilter] = None,
) -> Dict[str, Any]:
    """Generates defensive checklists using rule-based heuristics."""
    noise = noise or _noise_policy()
    risk_score = risk_assessment.get("risk_score", 50)
    host = alert.get("host") or "target host"
    malicious = list(_malicious_by_ioc(enrichments).values())
    corroborated = [m for m in malicious if len(m["sources"]) >= 2]
    peer_hosts = sorted({c.get("host") for c in correlations if c.get("host") and c.get("host") != alert.get("host")})
    techniques = [str(m.get("technique") or "") for m in mitre_mappings]

    checklist: List[str] = []
    containment_required = False

    if any(t.startswith("T1003") for t in techniques):
        containment_required = True
        checklist.append(f"Suggested (Requires human approval): Isolate '{host}' from the network: credential dumping exposes every account that logged on to it.")
        checklist.append(f"Reset passwords and revoke sessions for '{alert.get('user') or 'the executing account'}' and any privileged accounts cached on '{host}'.")
        checklist.append("Capture memory and the dumping process before remediation, then hunt for reuse of the dumped credentials (4624 logon type 3/10, 4648).")
        checklist.extend(_block_step(m, noise) for m in malicious)
        directive = f"Credential dumping on '{host}'. Suggested: Contain the host and rotate exposed credentials (requires human approval)."

    elif corroborated and peer_hosts:
        containment_required = True
        checklist.append(f"Suggested (Requires human approval): Isolate host '{host}' and review peers sharing indicators ({', '.join(peer_hosts[:3])}) for the same activity.")
        checklist.extend(_block_step(m, noise) for m in malicious)
        checklist.append("Inspect Active Directory authentication logs for unusual Kerberos tickets or lateral movement.")
        directive = f"Indicators corroborated by multiple threat-intel feeds appear on '{host}' and {len(peer_hosts)} other host(s). Suggested: Contain and scope."

    elif corroborated:
        containment_required = True
        checklist.append(f"Suggested (Requires human approval): Isolate endpoint '{host}' and terminate associated parent/child processes.")
        checklist.extend(_block_step(m, noise) for m in malicious)
        checklist.append("Perform full forensic triage and memory dump on the endpoint before remediation.")
        directive = f"Indicators corroborated by multiple threat-intel feeds on '{host}'. Suggested: Contain the host and validate scope."

    elif malicious:
        checklist.extend(_block_step(m, noise) for m in malicious)
        checklist.append(f"Inspect host '{host}' process tree and network connections around the alert time.")
        checklist.append("Contain only if the second source or host telemetry confirms the activity.")
        directive = f"Indicators on '{host}' were flagged by a single threat-intel feed. Validate before containment."

    elif "T1547.001" in techniques or "T1053.005" in techniques:
        checklist.append(f"Inspect Windows Registry under CurrentVersion\\Run and scheduled tasks on '{host}'.")
        checklist.append("Identify and remove unauthorized autostart binaries from AppData or Temp directories.")
        checklist.append("Review persistence artifacts and correlate execution timestamps against user logon sessions.")
        directive = f"Potential persistence mechanism identified on '{host}'. Inspect registry autostart keys and scheduled tasks."

    elif "T1110.001" in techniques or "4625" in str(alert.get("event_code", "")):
        checklist.append(f"Review target account '{alert.get('user', 'affected account')}' for signs of successful compromise (EventCode 4624).")
        checklist.append("Force password reset and terminate all active sessions if brute force was successful.")
        checklist.append(f"Suggested (Requires human approval): Block the offending source IP address ({alert.get('source_ip', 'external')}) on authentication gateway.")
        directive = "High-volume authentication failure detected. Verify account status and enforce password rotation if needed."

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
        "containment_advice": "suggested",
        "cited_evidence_ids": ["EVID-ALERT"],
        "engine": "deterministic_fallback",
    }


async def generate_recommendations_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Produces specific, actionable investigation and containment recommendations
    using Grok AI (with deterministic fallback).
    Enforces that containment is always suggested and requires human approval.
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
    org_id = alert.get("org_id", "default")
    logger.info("recommendation_agent_start", alert_id=alert_id)

    # 1. Build evidence catalog
    catalog = _build_evidence_catalog(alert, enrichments, correlations, mitre_mappings)
    valid_evidence_ids = set(catalog.keys())

    telemetry_input = {
        "alert": {
            "title": alert.get("title"),
            "host": alert.get("host"),
            "user": alert.get("user"),
            "severity": alert.get("severity"),
        },
        "risk_assessment": risk_assessment,
        "flagged_iocs": [
            {"ioc": e.get("ioc"), "reputation": e.get("reputation"), "source": e.get("source")}
            for e in enrichments if e.get("reputation") in ("malicious", "suspicious")
        ],
        "correlated_alerts_count": len(correlations),
        "timeline_events_count": len(timeline),
    }

    user_prompt = build_guarded_prompt(
        telemetry=telemetry_input,
        evidence_catalog=catalog,
        user_instruction="Generate actionable SOC recommendations and suggested containment checklist for this alert.",
    )

    # 2. Query LLM
    grok_response = await query_grok_llm(
        prompt=user_prompt,
        system_prompt=REC_SYSTEM_PROMPT,
        response_json=True,
        org_id=org_id,
    )
    parsed = extract_json_from_text(grok_response) if grok_response else None

    # 3. Validate citations
    is_valid_citation = _validate_rec_citations(parsed, valid_evidence_ids, alert) if parsed else False
    llm_meta = get_latest_query_metadata()

    if parsed and is_valid_citation and isinstance(parsed.get("recommendation"), str):
        directive = parsed["recommendation"]
        raw_checklist = parsed.get("checklist", [])
        
        # Enforce that containment actions are explicitly marked as suggested and requiring approval
        checklist = []
        for item in raw_checklist:
            text = str(item)
            if any(term in text.lower() for term in ("isolate", "block", "contain", "revoke", "disable user")):
                if not text.lower().startswith("suggested"):
                    text = f"Suggested (Requires human approval): {text}"
            checklist.append(text)

        formatted_rec = (
            f"{directive}\n\n"
            f"Actionable Steps (Containment advice is suggested; all automated actions require human approval):\n"
            + "\n".join(f"• {item}" for item in checklist)
        )
        log_msg = f"Grok AI Recommendation Agent: generated response checklist with {len(checklist)} step(s) via Grok"
        engine = f"llm:{settings.XAI_MODEL}"
    else:
        # Fallback to deterministic checklist
        rec_data = _deterministic_recommendation(alert, enrichments, correlations, mitre_mappings, risk_assessment, noise=await _tenant_noise_policy(org_id))
        directive = rec_data["recommendation"]
        checklist = rec_data["checklist"]
        formatted_rec = (
            f"{directive}\n\n"
            f"Actionable Steps (Containment advice is suggested; all automated actions require human approval):\n"
            + "\n".join(f"• {item}" for item in checklist)
        )
        log_msg = f"Recommendation Agent: generated response checklist with {len(checklist)} step(s) [Deterministic Engine]"
        engine = rec_data["engine"]

    logger.info("recommendation_agent_complete", alert_id=alert_id)
    new_log = current_log + [log_msg]

    return {
        "recommendation": formatted_rec,
        "recommendation_engine": engine,
        "investigation_log": new_log,
        "containment_advice": "suggested",
        "llm_metadata": llm_meta,
    }
