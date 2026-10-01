"""
MITRE ATT&CK Mapping Agent Node for LangGraph.
Maps alert indicators, detection rules, process activity, and telemetry
to the MITRE ATT&CK framework with taxonomy enrichment, tactics, and references.
"""

from typing import Dict, Any, List, Optional
import re
from app.core.logging import logger
from app.agents.state import AgentState

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Taxonomy Knowledge Base
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_CATALOG: Dict[str, Dict[str, str]] = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution, discovery, and defense evasion.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse cmd.exe to execute commands, scripts, or malicious batch files.",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding registry keys under CurrentVersion\\Run to execute programs at logon.",
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Execution",
        "description": "Adversaries may abuse the Windows Task Scheduler (schtasks.exe) to execute malicious code on a scheduled or recurring basis.",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to authenticate by guessing passwords across target accounts without prior password lists.",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may seek detailed information about the operating system, hardware, and architecture (e.g. systeminfo, whoami).",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of local or domain accounts to discover high-privilege targets.",
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for details about the network configuration and settings of the system (ipconfig, route).",
        "url": "https://attack.mitre.org/techniques/T1016/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts (port scanning).",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to identify other systems on a network through ping sweeps or network enumeration.",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS) to blend in with network noise.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversaries may log into an interactive session with systems over RDP to move laterally within an environment.",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use SMB to interact with remote file shares or execute commands on remote systems.",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use obfuscated commands, Base64 strings, or encoded payloads to hide execution from security monitoring.",
        "url": "https://attack.mitre.org/techniques/T1140/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or files from an external system into a compromised network (e.g. certutil, download cradles).",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs (e.g. via wevtutil) to hide evidence of intrusion and tamper with investigations.",
        "url": "https://attack.mitre.org/techniques/T1070/001/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from memory (LSASS) or disk to obtain plaintext passwords or password hashes.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable or modify security tools such as Windows Defender or EDR sensors to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
}

# Heuristic patterns mapped to techniques
PATTERN_RULES = [
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
]


def _build_mitre_entry(technique_id: str, evidence: str, confidence: str = "high") -> Dict[str, Any]:
    catalog_entry = ATTACK_CATALOG.get(technique_id, {})
    return {
        "technique": technique_id,
        "technique_id": technique_id,
        "name": catalog_entry.get("name", f"Technique {technique_id}"),
        "tactic": catalog_entry.get("tactic", "Execution"),
        "description": catalog_entry.get("description", "Technique mapped from alert telemetry."),
        "url": catalog_entry.get("url", f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"),
        "confidence": confidence,
        "evidence": evidence,
    }


def map_mitre_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Analyzes the alert and its extracted context to generate
    standardized MITRE ATT&CK technique and tactic mappings with evidence citations.
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    current_log = state.get("investigation_log", [])
    
    alert_id = str(alert.get("_id", "unknown"))
    logger.info("mitre_mapping_start", alert_id=alert_id)
    
    matched_techniques: Dict[str, Dict[str, Any]] = {}
    
    # 1. Direct mapping from alert metadata if present
    explicit_technique = alert.get("mitre_technique")
    if explicit_technique:
        # Some rules may store e.g. "T1059.001" or multiple "T1082 / T1087"
        for tech in re.findall(r"T\d{4}(?:\.\d{3})?", str(explicit_technique)):
            matched_techniques[tech] = _build_mitre_entry(
                technique_id=tech,
                evidence=f"Explicitly flagged by detection rule '{alert.get('rule_name', 'Rule')}'",
                confidence="high",
            )

    # 2. EventCode based mapping
    raw = alert.get("raw_event") or alert.get("raw_alert_data", {}).get("content", {})
    event_code = str(raw.get("EventCode") or alert.get("event_code") or "")
    
    if event_code == "4625":
        matched_techniques["T1110.001"] = _build_mitre_entry(
            technique_id="T1110.001",
            evidence="EventCode 4625: Multiple logon failures indicating credential brute force",
            confidence="high",
        )
    elif event_code == "13":
        target = str(context.get("registry_key") or raw.get("TargetObject") or "")
        if "currentversion\\run" in target.lower():
            matched_techniques["T1547.001"] = _build_mitre_entry(
                technique_id="T1547.001",
                evidence="EventCode 13: Registry Run key persistence modification",
                confidence="high",
            )
    elif event_code == "3":
        dest_port = str(context.get("dest_port") or raw.get("DestinationPort") or "")
        if dest_port in ("80", "443", "8080", "8443"):
            matched_techniques["T1071.001"] = _build_mitre_entry(
                technique_id="T1071.001",
                evidence=f"EventCode 3: Outbound network connection on standard web port {dest_port}",
                confidence="medium",
            )
        elif dest_port == "3389":
            matched_techniques["T1021.001"] = _build_mitre_entry(
                technique_id="T1021.001",
                evidence="EventCode 3: Network connection established over RDP (port 3389)",
                confidence="high",
            )

    # 3. Behavioral pattern heuristics across process names, command lines, and registry
    check_fields = {
        "process_name": str(context.get("process_name") or alert.get("process_name") or ""),
        "command_line": str(context.get("command_line") or alert.get("command_line") or ""),
        "registry_key": str(context.get("registry_key") or alert.get("registry_key") or ""),
    }
    
    for rule in PATTERN_RULES:
        tech_id = rule["technique_id"]
        field_val = check_fields.get(rule["field"], "")
        if field_val and rule["regex"].search(field_val):
            if tech_id not in matched_techniques:
                matched_techniques[tech_id] = _build_mitre_entry(
                    technique_id=tech_id,
                    evidence=rule["evidence"],
                    confidence="high",
                )

    mitre_mappings = list(matched_techniques.values())
    
    # Build logging summary
    if mitre_mappings:
        tech_list = ", ".join(f"{m['technique']} ({m['name']})" for m in mitre_mappings[:3])
        if len(mitre_mappings) > 3:
            tech_list += f" +{len(mitre_mappings)-3} more"
        log_entry = f"MITRE ATT&CK Agent: mapped {len(mitre_mappings)} technique(s): {tech_list}"
    else:
        log_entry = "MITRE ATT&CK Agent: no specific ATT&CK techniques matched alert heuristics"
        
    logger.info("mitre_mapping_complete", 
                alert_id=alert_id, 
                mapped_count=len(mitre_mappings))
                
    new_log = current_log + [log_entry]
    
    return {
        "mitre_mappings": mitre_mappings,
        "investigation_log": new_log
    }
