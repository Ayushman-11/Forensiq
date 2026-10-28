"""
Correlation Agent Node for LangGraph.
Analyzes current alert context and IOCs against historical telemetry in MongoDB to discover
related attack activity, multi-host campaigns, and repeated IOC sightings.
"""

from typing import Dict, Any, List
from app.core.logging import logger
from app.agents.state import AgentState
from app.database.session import get_db
from app.services.correlation import correlate_alert


async def correlate_events_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Correlates the current alert against historical alerts in MongoDB
    using host, user, network addresses, process names, and extracted IOCs.
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    extracted_iocs = state.get("extracted_iocs", [])
    current_log = state.get("investigation_log", [])
    
    alert_id = str(alert.get("_id", "unknown"))
    logger.info("correlation_node_start", alert_id=alert_id)
    
    # Merge context into alert payload so correlation matches on extracted attributes
    merged_alert = dict(alert)
    for field in ("host", "user", "source_ip", "dest_ip", "process_name"):
        if not merged_alert.get(field) and context.get(field):
            merged_alert[field] = context[field]
            
    # Include all extracted IOCs (both initially present and context-extracted)
    all_iocs = set(merged_alert.get("extracted_iocs", []) or [])
    all_iocs.update(extracted_iocs)
    merged_alert["extracted_iocs"] = list(all_iocs)
    
    correlations: List[Dict[str, Any]] = []
    try:
        db = await get_db()
        correlations = await correlate_alert(db, merged_alert)
    except Exception as e:
        logger.error("correlation_node_failed", alert_id=alert_id, error=str(e))
        new_log = current_log + ["Correlation Agent could not complete (see server logs)"]
        return {
            "correlations": [],
            "investigation_log": new_log
        }
    
    # Build detailed summary for analyst log
    if correlations:
        correlated_hosts = {c.get("host") for c in correlations if c.get("host")}
        correlated_severities = [c.get("severity", "unknown") for c in correlations]
        high_crit_count = sum(1 for s in correlated_severities if str(s).lower() in ("critical", "high"))
        
        summary_msg = (
            f"Correlation Agent: found {len(correlations)} related historical alert(s) "
            f"across {len(correlated_hosts)} host(s) ({high_crit_count} high/critical)"
        )
    else:
        summary_msg = "Correlation Agent: no historical alert correlations found for this entity"
        
    logger.info("correlation_node_complete", 
                alert_id=alert_id, 
                correlations_count=len(correlations))
                
    new_log = current_log + [summary_msg]
    return {
        "correlations": correlations,
        "investigation_log": new_log
    }
