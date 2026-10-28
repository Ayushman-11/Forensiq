from typing import Dict, Any
from app.core.logging import logger
from app.agents.state import AgentState
from app.normalization.ioc import public_domain, public_ip

def extract_context_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Parses the raw alert payload to extract contextual information and IOCs.
    """
    alert_data = state.get("alert_data", {})
    logger.info("context_node_start", alert_id=alert_data.get("_id"))
    
    # The new pipeline stores all top-level keys in raw_event
    raw = alert_data.get("raw_event", {})
    if not raw:
        # Fallback for old mock data
        raw = alert_data.get("raw_alert_data", {}).get("content", {})
        
    event_code = str(raw.get("EventCode", ""))
    
    context = {}
    
    if event_code == "1":
        context["process_name"] = raw.get("Image")
        context["command_line"] = raw.get("CommandLine")
        context["parent_process"] = raw.get("ParentImage")
        context["hashes"] = raw.get("Hashes")
        context["user"] = raw.get("User")
    elif event_code == "3":
        context["process_name"] = raw.get("Image")
        context["source_ip"] = raw.get("SourceIp")
        context["dest_ip"] = raw.get("DestinationIp")
        context["dest_port"] = raw.get("DestinationPort")
        context["protocol"] = raw.get("Protocol")
    elif event_code == "13":
        context["registry_key"] = raw.get("TargetObject")
        context["registry_details"] = raw.get("Details")
        context["process_name"] = raw.get("Image")
    elif event_code == "22":
        context["dns_query"] = raw.get("QueryName")
        context["process_name"] = raw.get("Image")
        context["resolved_ips"] = raw.get("QueryResults")
    elif event_code == "4625":
        context["target_user"] = raw.get("TargetUserName")
        context["source_ip"] = raw.get("IpAddress")
        context["logon_type"] = raw.get("LogonType")
        context["failure_reason"] = raw.get("FailureReason")
        context["workstation"] = raw.get("WorkstationName")
    elif event_code == "4648":
        context["subject_user"] = raw.get("SubjectUserName")
        context["target_user"] = raw.get("TargetUserName")
        context["source_ip"] = raw.get("IpAddress")
    elif event_code == "4688":
        context["process_name"] = raw.get("NewProcessName")
        context["parent_process"] = raw.get("ParentProcessName")
        context["command_line"] = raw.get("CommandLine")
        context["user"] = raw.get("SubjectUserName")
    elif event_code == "4104":
        script_block = raw.get("ScriptBlockText", "")
        # Truncate script block for context to prevent massive payloads
        context["script_block"] = script_block[:2000] + "..." if len(script_block) > 2000 else script_block

    # Clean up empty values in context
    context = {k: v for k, v in context.items() if v}
    
    # We already have IOCs extracted during ingestion, but we can augment them
    existing_iocs = set(alert_data.get("extracted_iocs", []))
    
    # Re-extract just in case, using the shared global-address check
    for candidate in (raw.get("SourceIp"), raw.get("DestinationIp"), raw.get("IpAddress")):
        ip = public_ip(candidate)
        if ip:
            existing_iocs.add(ip)
    query_name = raw.get("QueryName")
    if isinstance(query_name, str) and query_name.strip() not in ("", "-"):
        domain = public_domain(query_name, allow_file_tlds=True)
        if domain:
            existing_iocs.add(domain)

    extracted_iocs = list(existing_iocs)
    
    logger.info("context_node_complete", 
                alert_id=alert_data.get("_id", ""), 
                extracted_iocs=len(extracted_iocs))
    
    current_log = state.get("investigation_log", [])
    new_log = current_log + [f"Context extraction complete: found {len(context)} key properties and {len(extracted_iocs)} IOCs"]
    
    return {
        "context": context,
        "extracted_iocs": extracted_iocs,
        "investigation_log": new_log
    }
