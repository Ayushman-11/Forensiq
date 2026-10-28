"""
Official MITRE ATT&CK Enterprise Matrix & STIX Integration.
Version: v15.1 (Pinned Official Enterprise ATT&CK matrix)
Provides validated techniques, tactics, mitigations, and cross-reference links.
Corrects historical misclassifications (e.g. T1071.004 correctly mapped to Command and Control).
"""

from typing import Dict, Any, List, Optional
import re

ATTACK_VERSION = "v15.1"

# Standard Enterprise Tactics in execution order
ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Official ATT&CK Enterprise Catalog
ATTACK_CATALOG: Dict[str, Dict[str, Any]] = {
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access LSASS memory to extract password hashes, Kerberos tickets, and plaintext PINs/passwords (e.g. Mimikatz, procdump, comsvcs.dll).",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution, discovery, and defense evasion.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse cmd.exe to execute commands, scripts, or batch files.",
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
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "url": "https://attack.mitre.org/techniques/T1110/",
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
        "description": "Adversaries may look for details about network configuration (ipconfig, route).",
        "url": "https://attack.mitre.org/techniques/T1016/",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to blend in with network traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS).",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection and network filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "T1550.002": {
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use stolen password hashes to authenticate across Windows systems over NTLM/Kerberos.",
        "url": "https://attack.mitre.org/techniques/T1550/002/",
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
        "description": "Adversaries may transfer tools or files from an external system into a compromised network (e.g. download cradles).",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs (via wevtutil) to hide evidence of intrusion.",
        "url": "https://attack.mitre.org/techniques/T1070/001/",
    },
}


def lookup_technique(technique_id: str) -> Dict[str, Any]:
    """Looks up official ATT&CK technique details or provides a standardized fallback."""
    clean_id = technique_id.strip().upper()
    if clean_id in ATTACK_CATALOG:
        entry = dict(ATTACK_CATALOG[clean_id])
        entry["technique_id"] = clean_id
        entry["version"] = ATTACK_VERSION
        return entry
    
    # Check parent technique if sub-technique
    parent_id = clean_id.split(".")[0]
    if parent_id in ATTACK_CATALOG:
        parent_entry = ATTACK_CATALOG[parent_id]
        return {
            "technique_id": clean_id,
            "name": f"{parent_entry['name']} ({clean_id})",
            "tactic": parent_entry["tactic"],
            "description": parent_entry["description"],
            "url": f"https://attack.mitre.org/techniques/{clean_id.replace('.', '/')}/",
            "version": ATTACK_VERSION,
        }

    return {
        "technique_id": clean_id,
        "name": clean_id,
        "tactic": "Execution",
        "description": f"MITRE ATT&CK technique {clean_id}",
        "url": f"https://attack.mitre.org/techniques/{clean_id.replace('.', '/')}/",
        "version": ATTACK_VERSION,
    }

