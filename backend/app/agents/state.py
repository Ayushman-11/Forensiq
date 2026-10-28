from typing import Any, TypedDict


class AgentState(TypedDict):
    """
    Represents the state of an investigation traversing the LangGraph workflow.
    """
    # The raw alert payload ingested from the SIEM
    alert_data: dict[str, Any]

    # Context extracted by the Context Agent
    context: dict[str, Any]

    # Extracted IOCs (e.g., IPs, domains, hashes)
    extracted_iocs: list[str]

    # Intelligence retrieved by the IOC Enrichment Agent
    enrichment_results: list[dict[str, Any]]

    # Human-readable investigation log
    investigation_log: list[str]

    # Final AI insights/summary (reserved for future LLM nodes)
    ai_analysis: str | None

    # Transparent MVP decision layer outputs
    correlations: list[dict[str, Any]]
    risk_assessment: dict[str, Any]
    mitre_mappings: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    recommendation: str | None
