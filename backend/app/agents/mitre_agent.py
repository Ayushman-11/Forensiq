"""
MITRE ATT&CK Mapping Agent Node for LangGraph.
Maps alert indicators, detection rules, process activity, and telemetry
to the pinned official MITRE ATT&CK Enterprise Matrix (v15.1) with taxonomy enrichment.
"""

from typing import Dict, Any, List, Optional
import re
from app.core.logging import logger
from app.agents.state import AgentState
from app.core.mitre_stix import lookup_technique, ATTACK_VERSION, ATTACK_CATALOG

# Heuristic patterns mapped to official techniques
PATTERN_RULES = [
    {
        "technique_id": "T1003.001",
        "regex": re.compile(r"(sekurlsa|logonpasswords|invoke-mimikatz|mimikatz|lsass\.exe|procdump.*lsass|comsvcs.*minidump)", re.IGNORECASE),
        "field": "command_line",
        "evidence": "OS Credential Dumping / Mimikatz LSASS memory extraction pattern detected",
    },
    {
        "technique_id": "T1059.001",
        "regex": re.compile(r"(powershell|pwsh)(\.exe)?", re.IGNORECASE),
        "field": "process_name",
        "evidence": "PowerShell process execution detected",
    },
    {
        "technique_id": "T1140",
        "regex": re.compile(r"(-enc|-encodedcommand|frombase64string|gzipstream)", re.IGNORECASE),
        "field": "command_line",
        "evidence": "Base64 or obfuscated command line parameter detected",
    },
    {
        "technique_id": "T1105",
        "regex": re.compile(r"(downloadstring|webrequest|certutil.*-urlcache|bitsadmin.*transfer)", re.IGNORECASE),
        "field": "command_line",
        "evidence": "Remote file download cradle detected in command line",
    },
    {
        "technique_id": "T1053.005",
        "regex": re.compile(r"schtasks(\.exe)?.*(/create|/run)", re.IGNORECASE),
        "field": "command_line",
        "evidence": "Scheduled task creation or dispatch via schtasks.exe",
    },
    {
        "technique_id": "T1547.001",
        "regex": re.compile(r"currentversion\\(run|runonce)", re.IGNORECASE),
        "field": "registry_key",
        "evidence": "Run key persistence configured in Windows Registry",
    },
    {
        "technique_id": "T1082",
        "regex": re.compile(r"(whoami|systeminfo)(\.exe)?", re.IGNORECASE),
        "field": "process_name",
        "evidence": "System information reconnaissance tool executed",
    },
    {
        "technique_id": "T1087",
        "regex": re.compile(r"net(\.exe)?\s+(user|group)", re.IGNORECASE),
        "field": "command_line",
        "evidence": "User or group account discovery command executed",
    },
    {
        "technique_id": "T1016",
        "regex": re.compile(r"(ipconfig|route|nltest)(\.exe)?", re.IGNORECASE),
        "field": "process_name",
        "evidence": "Network configuration discovery command executed",
    },
    {
        "technique_id": "T1070.001",
        "regex": re.compile(r"wevtutil.*(cl|clear-log)", re.IGNORECASE),
        "field": "command_line",
        "evidence": "Windows event log clearing command detected",
    },
    {
        "technique_id": "T1071.004",
        "regex": re.compile(r"(dyndns|ngrok\.io|duckdns\.org|no-ip\.com)", re.IGNORECASE),
        "field": "dns_query",
        "evidence": "DNS tunneling or suspicious dynamic DNS domain query detected",
    },
]


def _build_mitre_entry(technique_id: str, evidence: str, confidence: str = "high") -> Dict[str, Any]:
    catalog_entry = lookup_technique(technique_id)
    return {
        "technique": technique_id,
        "technique_id": technique_id,
        "name": catalog_entry.get("name"),
        "tactic": catalog_entry.get("tactic"),
        "description": catalog_entry.get("description"),
        "url": catalog_entry.get("url"),
        "attack_version": ATTACK_VERSION,
        "confidence": confidence,
        "evidence": evidence,
    }


def map_mitre_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Analyzes the alert and its extracted context to generate
    standardized MITRE ATT&CK technique and tactic mappings with official STIX metadata.
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    current_log = state.get("investigation_log", [])
    
    alert_id = str(alert.get("_id", "unknown"))
    logger.info("mitre_mapping_start", alert_id=alert_id)
    
    matched_techniques: Dict[str, Dict[str, Any]] = {}
    
    # 1. Direct mapping from alert metadata
    explicit_technique = alert.get("mitre_technique")
    if explicit_technique:
        for tech in re.findall(r"T\d{4}(?:\.\d{3})?", str(explicit_technique)):
            matched_techniques[tech] = _build_mitre_entry(
                technique_id=tech,
                evidence=f"Explicitly flagged by detection rule '{alert.get('rule_name', 'Rule')}'",
                confidence="high",
            )
            
    # 2. Check detection rule name for Mimikatz / Credential Dumping
    rule_name = str(alert.get("rule_name", "")).lower()
    if "mimikatz" in rule_name or "credential" in rule_name or "lsass" in rule_name:
        matched_techniques["T1003.001"] = _build_mitre_entry(
            technique_id="T1003.001",
            evidence="Rule indicates LSASS memory dumping / Mimikatz activity",
            confidence="high",
        )
    
    # 3. Rule matching against telemetry fields
    combined = {**alert, **context}
    for rule in PATTERN_RULES:
        tech_id = rule["technique_id"]
        field_val = str(combined.get(rule["field"]) or "")
        if field_val and rule["regex"].search(field_val):
            if tech_id not in matched_techniques:
                matched_techniques[tech_id] = _build_mitre_entry(
                    technique_id=tech_id,
                    evidence=f"{rule['evidence']} (matched on field '{rule['field']}')",
                    confidence="medium",
                )
                
    mappings_list = list(matched_techniques.values())
    summary = f"MITRE Agent: mapped {len(mappings_list)} technique(s) from ATT&CK {ATTACK_VERSION}"
    logger.info("mitre_mapping_complete", alert_id=alert_id, count=len(mappings_list))
    
    return {
        "mitre_mappings": mappings_list,
        "investigation_log": current_log + [summary],
    }
