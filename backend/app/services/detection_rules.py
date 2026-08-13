"""
DetectionRuleEngine – static registry of MITRE-mapped detection rules.

Each rule carries:
  - name            : unique rule identifier
  - description     : human-readable description
  - severity        : critical | high | medium | low
  - alert_type      : logical category for UI grouping
  - mitre_technique : ATT&CK technique ID
  - mitre_tactic    : ATT&CK tactic phase
  - spl_query       : complete Splunk SPL executed by IngestionService
  - event_codes     : list of Sysmon/Security EventCodes this rule targets
                      (used by evaluate_raw_event for fast local matching)
  - match_fn        : optional callable(raw: dict) -> bool for local evaluation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    name: str
    description: str
    severity: str               # critical | high | medium | low
    alert_type: str
    mitre_technique: str
    mitre_tactic: str
    spl_query: str
    event_codes: List[str] = field(default_factory=list)
    match_fn: Optional[Callable[[dict], bool]] = field(default=None, repr=False, compare=False)


# ---------------------------------------------------------------------------
# Helper predicates
# ---------------------------------------------------------------------------

_PRIVATE_IP_PATTERN = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|\:\:1)"
)


def _is_private_ip(ip: str) -> bool:
    return bool(_PRIVATE_IP_PATTERN.match(str(ip or "")))


def _field_contains_any(raw: dict, field_name: str, patterns: List[str]) -> bool:
    value = str(raw.get(field_name) or "").lower()
    return any(p.lower() in value for p in patterns)


def _suspicious_powershell(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "1":
        return False
    image = str(raw.get("Image") or "").lower()
    if "powershell" not in image and "pwsh" not in image:
        return False
    cmd = str(raw.get("CommandLine") or "").lower()
    suspicious_terms = [
        "-enc", "-encodedcommand", "-noni", "-noninteractive",
        "bypass", "hidden", "downloadstring", "iex", "webclient",
        "invoke-expression", "invoke-webrequest",
    ]
    return any(t in cmd for t in suspicious_terms)


def _registry_persistence(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "13":
        return False
    target = str(raw.get("TargetObject") or "").lower()
    return "currentversion\\run" in target or "currentversion/run" in target


def _external_network(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "3":
        return False
    initiated = str(raw.get("Initiated") or "").lower()
    if initiated not in ("true", "1", "yes"):
        return False
    dest_ip = str(raw.get("DestinationIp") or "")
    if not dest_ip or _is_private_ip(dest_ip):
        return False
    try:
        dest_port = int(raw.get("DestinationPort") or 0)
    except (ValueError, TypeError):
        dest_port = 0
    return dest_port not in (80, 443, 53, 0)


def _dns_suspicious(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "22":
        return False
    qname = str(raw.get("QueryName") or "").lower()
    suspicious_patterns = ["dyndns", "ngrok", "pastebin", "raw.githubusercontent", "bit.ly"]
    if any(p in qname for p in suspicious_patterns):
        return True
    return len(qname) > 60


def _powershell_script_block(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "4104":
        return False
    text = str(raw.get("ScriptBlockText") or "").lower()
    patterns = ["invoke-expression", "iex", "net.webclient", "downloadstring", "bypass"]
    return any(p in text for p in patterns)


def _brute_force(raw: dict) -> bool:
    """
    For aggregate/grouped results from Splunk stats query.
    The SPL returns rows with {IpAddress, TargetUserName, count}.
    """
    ec = str(raw.get("EventCode", ""))
    if ec and ec != "4625":
        return False
    try:
        count = int(raw.get("count") or 0)
        return count >= 5
    except (ValueError, TypeError):
        return False


def _lateral_movement(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "4648":
        return False
    subject = str(raw.get("SubjectUserName") or "")
    target = str(raw.get("TargetUserName") or "")
    return subject not in ("", "-") and target not in ("", "-")


def _process_anomaly(raw: dict) -> bool:
    """
    EC4688 suspicious parent/child combos.
    Flag when Office or browser apps spawn cmd/powershell/wscript.
    """
    ec = str(raw.get("EventCode", ""))
    if ec != "4688":
        return False
    new_proc = str(raw.get("NewProcessName") or "").lower()
    parent_proc = str(raw.get("ParentProcessName") or "").lower()
    suspicious_children = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    suspicious_parents = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe"]
    return (
        any(c in new_proc for c in suspicious_children)
        and any(p in parent_proc for p in suspicious_parents)
    )


# ---------------------------------------------------------------------------
# Rule Registry
# ---------------------------------------------------------------------------

_RULES: List[DetectionRule] = [
    DetectionRule(
        name="brute_force_login",
        description=(
            "Detects brute force attacks: 5 or more failed logon attempts (EC4625) "
            "from the same IP address within the polling window."
        ),
        severity="high",
        alert_type="Brute Force",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Security\" EventCode=4625 "
            "| stats count by IpAddress, TargetUserName "
            "| where count >= 5"
        ),
        event_codes=["4625"],
        match_fn=_brute_force,
    ),
    DetectionRule(
        name="suspicious_powershell_execution",
        description=(
            "Detects suspicious PowerShell process creation (Sysmon EC1) with encoded, "
            "bypass, hidden, or download cradle indicators in the command line."
        ),
        severity="critical",
        alert_type="Malicious PowerShell",
        mitre_technique="T1059.001",
        mitre_tactic="Execution",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" "
            "EventCode=1 "
            "(Image=\"*powershell*\" OR Image=\"*pwsh*\") "
            "(CommandLine=\"*-enc*\" OR CommandLine=\"*-EncodedCommand*\" OR "
            "CommandLine=\"*-NonI*\" OR CommandLine=\"*bypass*\" OR "
            "CommandLine=\"*hidden*\" OR CommandLine=\"*downloadstring*\" OR "
            "CommandLine=\"*IEX*\" OR CommandLine=\"*WebClient*\")"
        ),
        event_codes=["1"],
        match_fn=_suspicious_powershell,
    ),
    DetectionRule(
        name="registry_run_key_persistence",
        description=(
            "Detects persistence via Windows Registry Run keys (Sysmon EC13): "
            "modification of HKLM/HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run."
        ),
        severity="high",
        alert_type="Registry Persistence",
        mitre_technique="T1547.001",
        mitre_tactic="Persistence",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" "
            "EventCode=13 TargetObject=\"*CurrentVersion\\\\Run*\""
        ),
        event_codes=["13"],
        match_fn=_registry_persistence,
    ),
    DetectionRule(
        name="suspicious_external_connection",
        description=(
            "Detects Sysmon EC3 outbound network connections to non-private IP ranges "
            "on non-standard ports (excluding 80, 443, 53). Potential C2 beaconing."
        ),
        severity="medium",
        alert_type="Suspicious Network Connection",
        mitre_technique="T1071",
        mitre_tactic="Command and Control",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" "
            "EventCode=3 Initiated=true "
            "NOT (DestinationIp=\"10.*\" OR DestinationIp=\"192.168.*\" OR "
            "DestinationIp=\"172.*\" OR DestinationIp=\"127.*\") "
            "NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=53)"
        ),
        event_codes=["3"],
        match_fn=_external_network,
    ),
    DetectionRule(
        name="dns_suspicious_query",
        description=(
            "Detects Sysmon EC22 DNS queries to known suspicious domains "
            "(dyndns, ngrok, pastebin, raw.githubusercontent, bit.ly) or "
            "unusually long domain names (>60 chars) indicating DNS tunneling."
        ),
        severity="medium",
        alert_type="DNS Tunneling / Suspicious DNS",
        mitre_technique="T1071.004",
        mitre_tactic="Command and Control",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" "
            "EventCode=22 "
            "(QueryName=\"*dyndns*\" OR QueryName=\"*ngrok*\" OR QueryName=\"*pastebin*\" "
            "OR QueryName=\"*raw.githubusercontent*\" OR QueryName=\"*bit.ly*\")"
        ),
        event_codes=["22"],
        match_fn=_dns_suspicious,
    ),
    DetectionRule(
        name="powershell_script_block_logging",
        description=(
            "Detects PowerShell Script Block Logging events (EC4104) containing "
            "Invoke-Expression, IEX, Net.WebClient, DownloadString, or bypass. "
            "Indicates script-based attack or living-off-the-land technique."
        ),
        severity="critical",
        alert_type="Malicious PowerShell",
        mitre_technique="T1059.001",
        mitre_tactic="Execution",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Microsoft-Windows-PowerShell/Operational\" "
            "EventCode=4104 "
            "(ScriptBlockText=\"*Invoke-Expression*\" OR ScriptBlockText=\"*IEX*\" OR "
            "ScriptBlockText=\"*Net.WebClient*\" OR ScriptBlockText=\"*DownloadString*\" "
            "OR ScriptBlockText=\"*bypass*\")"
        ),
        event_codes=["4104"],
        match_fn=_powershell_script_block,
    ),
    DetectionRule(
        name="lateral_movement_explicit_credentials",
        description=(
            "Detects explicit credential use (EC4648) from one account authenticating "
            "as another, a common lateral movement technique."
        ),
        severity="high",
        alert_type="Lateral Movement",
        mitre_technique="T1550.002",
        mitre_tactic="Lateral Movement",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Security\" EventCode=4648 "
            "NOT SubjectUserName=\"-\" NOT TargetUserName=\"-\""
        ),
        event_codes=["4648"],
        match_fn=_lateral_movement,
    ),
    DetectionRule(
        name="process_creation_anomaly",
        description=(
            "Detects suspicious parent-child process relationships (EC4688): "
            "Office apps or browsers spawning command interpreters or scripting engines, "
            "indicative of macro execution or drive-by exploitation."
        ),
        severity="medium",
        alert_type="Process Anomaly",
        mitre_technique="T1566.001",
        mitre_tactic="Initial Access",
        spl_query=(
            "search index=windows source=\"XmlWinEventLog:Security\" EventCode=4688 "
            "(ParentProcessName=\"*winword*\" OR ParentProcessName=\"*excel*\" OR "
            "ParentProcessName=\"*powerpnt*\" OR ParentProcessName=\"*outlook*\" OR "
            "ParentProcessName=\"*chrome*\" OR ParentProcessName=\"*firefox*\" OR "
            "ParentProcessName=\"*iexplore*\" OR ParentProcessName=\"*msedge*\") "
            "(NewProcessName=\"*cmd.exe*\" OR NewProcessName=\"*powershell.exe*\" OR "
            "NewProcessName=\"*pwsh.exe*\" OR NewProcessName=\"*wscript.exe*\" OR "
            "NewProcessName=\"*cscript.exe*\" OR NewProcessName=\"*mshta.exe*\")"
        ),
        event_codes=["4688"],
        match_fn=_process_anomaly,
    ),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DetectionRuleEngine:
    """
    Registry and evaluation engine for all Forensiq detection rules.

    Usage
    -----
    engine = DetectionRuleEngine()
    rules  = engine.get_all_rules()
    result = engine.evaluate_raw_event(raw_splunk_dict)
    """

    def get_all_rules(self) -> List[DetectionRule]:
        """Returns the complete list of registered DetectionRule objects."""
        return list(_RULES)

    def evaluate_raw_event(self, raw: dict) -> Optional[Dict]:
        """
        Evaluates a single raw Splunk event dict against every rule's match_fn.

        Returns the *first* matching rule's metadata dict, or None if no rule matches.
        The returned dict contains:
            rule_name, description, severity, alert_type,
            mitre_technique, mitre_tactic
        """
        for rule in _RULES:
            if rule.match_fn is None:
                continue
            try:
                if rule.match_fn(raw):
                    return {
                        "rule_name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "alert_type": rule.alert_type,
                        "mitre_technique": rule.mitre_technique,
                        "mitre_tactic": rule.mitre_tactic,
                    }
            except Exception:
                # Defensive: never crash the pipeline due to a bad event field
                continue
        return None

    def get_rule_by_name(self, name: str) -> Optional[DetectionRule]:
        """Returns the DetectionRule with the given name, or None."""
        for rule in _RULES:
            if rule.name == name:
                return rule
        return None
