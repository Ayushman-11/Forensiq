from typing import TypedDict, List, Dict, Any, Optional

class AgentState(TypedDict):
    """
    Represents the state of an investigation traversing the LangGraph workflow.
    """
    # The raw alert payload ingested from the SIEM
    alert_data: Dict[str, Any]
    
    # Context extracted by the Context Agent
    context: Dict[str, Any]
    
    # Extracted IOCs (e.g., IPs, domains, hashes)
    extracted_iocs: List[str]
    
    # Intelligence retrieved by the IOC Enrichment Agent
    enrichment_results: List[Dict[str, Any]]
    
    # Human-readable investigation log
    investigation_log: List[str]
    
    # Final AI insights/summary (reserved for future LLM nodes)
    ai_analysis: Optional[str]
