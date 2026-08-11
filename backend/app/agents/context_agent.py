from typing import Dict, Any
from app.core.logging import logger
from app.agents.state import AgentState

def extract_context_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Parses the raw alert payload to extract contextual information and IOCs.
    """
    alert_data = state.get("alert_data", {})
    logger.info("context_node_start", alert_id=alert_data.get("_id"))
    
    raw = alert_data.get("raw_alert_data", {})
    content = raw.get("content", {}) if isinstance(raw, dict) else {}
    
    # Extract IPs
    ips = set()
    src_ip = content.get("src_ip") or content.get("SourceIp")
    dest_ip = content.get("dest_ip") or content.get("DestinationIp")
    if src_ip: ips.add(src_ip)
    if dest_ip: ips.add(dest_ip)
    
    # Extract Domains
    domains = set()
    domain = content.get("domain") or content.get("QueryName")
    if domain: domains.add(domain)
    
    extracted_iocs = list(ips) + list(domains)
    
    logger.info("context_node_complete", 
                alert_id=alert_data.get("_id", ""), 
                extracted_iocs=len(extracted_iocs))
    
    return {"extracted_iocs": extracted_iocs}
