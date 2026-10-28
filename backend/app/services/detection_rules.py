"""
Dynamic Detection Rule Engine.
Supports loading declarative YAML detection rules with metadata, owners, test tags,
fast regex matching, and execution of built-in and dynamic rules.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional
import yaml

from app.core.logging import logger
from app.core.mitre_stix import lookup_technique, ATTACK_VERSION
from app.normalization.ioc import public_ip



@dataclass
class DetectionRule:
    name: str
    description: str
    severity: str # critical | high | medium | low
    alert_type: str
    mitre_technique: str
    mitre_tactic: str
    event_codes: List[str] = field(default_factory=list)
    spl_query: str = ""
    owner: str = "Detection Engineering"
    tags: List[str] = field(default_factory=list)
    last_fired: Optional[datetime] = None
    fire_count: int = 0
    patterns: List[Dict[str, Any]] = field(default_factory=list)
    match_fn: Optional[Callable[[dict], bool]] = field(default=None, repr=False, compare=False)


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------

def _is_external_ip(ip: str) -> bool:
    """True only for globally routable, non-multicast addresses (v4 or v6, incl. IPv4-mapped)."""
    return public_ip(str(ip or "")) is not None


def _mimikatz_dump(raw: dict) -> bool:
    """EC1 or EC4104 or EC4688: Detects Mimikatz invocation / LSASS dump."""
    cmd = str(raw.get("CommandLine") or raw.get("ScriptBlockText") or "").lower()
    terms = ["sekurlsa", "logonpasswords", "invoke-mimikatz", "mimikatz", "comsvcs", "minidump"]
    if any(t in cmd for t in terms):
        # Correlate with lsass target or explicit mimikatz flag
        if "mimikatz" in cmd or "lsass" in cmd or "sekurlsa" in cmd:
            return True
    return False


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
    if not dest_ip or not _is_external_ip(dest_ip):
        return False
    try:
        dest_port = int(raw.get("DestinationPort") or 0)
    except (ValueError, TypeError):
        dest_port = 0
    return dest_port not in (80, 443, 53, 0)


def _dns_suspicious_domain_lookup(raw: dict) -> bool:
    """
    EC22: Flag fast-flux/dynamic DNS domains and suspicious C2 staging.
    Excludes benign developer repositories (github.com, raw.githubusercontent.com)
    to prevent false positives.
    """
    ec = str(raw.get("EventCode", ""))
    if ec != "22":
        return False
    qname = str(raw.get("QueryName") or "").lower()
    # Explicit exclusions for normal developer/IT lookups
    if any(whitelisted in qname for whitelisted in ("github.com", "githubusercontent.com", "microsoft.com", "windows.com")):
        return False

    suspicious_patterns = ["dyndns", "ngrok.io", "duckdns.org", "no-ip.com", "pastebin.com"]
    if any(p in qname for p in suspicious_patterns):
        return True
    return len(qname) > 85 # Higher threshold to avoid benign CDNs


def _powershell_script_block(raw: dict) -> bool:
    ec = str(raw.get("EventCode", ""))
    if ec != "4104":
        return False
    text = str(raw.get("ScriptBlockText") or "").lower()
    patterns = ["invoke-expression", "iex", "net.webclient", "downloadstring", "bypass"]
    return any(p in text for p in patterns)


def _brute_force(raw: dict) -> bool:
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
# Engine with YAML Loader
# ---------------------------------------------------------------------------

class DetectionRuleEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self._rules: Dict[str, DetectionRule] = {}
        self.rules_dir = rules_dir or str(Path(__file__).resolve().parent.parent.parent / "rules")
        self._register_defaults()
        self.load_yaml_rules()

    def _register_defaults(self):
        defaults = [
            DetectionRule(
                name="mimikatz_credential_dumping",
                description="Detects Mimikatz invocation, LSASS memory dumping, or sekurlsa module execution (Atomic Red Team T1003).",
                severity="critical",
                alert_type="Credential Access",
                mitre_technique="T1003.001",
                mitre_tactic="Credential Access",
                event_codes=["1", "4104", "4688"],
                match_fn=_mimikatz_dump,
                owner="Detection Engineering",
                tags=["atomic-red-team", "credential-dumping", "mimikatz"],
            ),
            DetectionRule(
                name="brute_force_login",
                description="Detects brute force attacks: 5 or more failed logon attempts (EC4625).",
                severity="high",
                alert_type="Brute Force",
                mitre_technique="T1110",
                mitre_tactic="Credential Access",
                event_codes=["4625"],
                match_fn=_brute_force,
                owner="Identity Security",
            ),
            DetectionRule(
                name="suspicious_powershell_execution",
                description="Detects suspicious PowerShell process creation (Sysmon EC1) with encoded or download cradles.",
                severity="critical",
                alert_type="Malicious PowerShell",
                mitre_technique="T1059.001",
                mitre_tactic="Execution",
                event_codes=["1"],
                match_fn=_suspicious_powershell,
                owner="Endpoint Defense",
            ),
            DetectionRule(
                name="registry_run_key_persistence",
                description="Detects persistence via Windows Registry Run keys (Sysmon EC13).",
                severity="high",
                alert_type="Registry Persistence",
                mitre_technique="T1547.001",
                mitre_tactic="Persistence",
                event_codes=["13"],
                match_fn=_registry_persistence,
                owner="Endpoint Defense",
            ),
            DetectionRule(
                name="suspicious_external_connection",
                description="Detects outbound network connections to non-private IPs on non-standard ports.",
                severity="medium",
                alert_type="Suspicious Network Connection",
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                event_codes=["3"],
                match_fn=_external_network,
                owner="Network Security",
            ),
            DetectionRule(
                name="dns_suspicious_domain_lookup",
                description="Detects DNS queries to suspicious dynamic DNS providers or tunneling infrastructure.",
                severity="medium",
                alert_type="Suspicious Domain Lookup",
                mitre_technique="T1071.004",
                mitre_tactic="Command and Control",
                event_codes=["22"],
                match_fn=_dns_suspicious_domain_lookup,
                owner="Network Security",
            ),
            DetectionRule(
                name="powershell_script_block_logging",
                description="Detects PowerShell Script Block Logging events (EC4104) containing malicious cradles.",
                severity="critical",
                alert_type="Malicious PowerShell",
                mitre_technique="T1059.001",
                mitre_tactic="Execution",
                event_codes=["4104"],
                match_fn=_powershell_script_block,
                owner="Endpoint Defense",
            ),
            DetectionRule(
                name="lateral_movement_explicit_credentials",
                description="Detects explicit credential use (EC4648) from one account authenticating as another.",
                severity="high",
                alert_type="Lateral Movement",
                mitre_technique="T1550.002",
                mitre_tactic="Lateral Movement",
                event_codes=["4648"],
                match_fn=_lateral_movement,
                owner="Identity Security",
            ),
            DetectionRule(
                name="process_creation_anomaly",
                description="Detects suspicious parent-child process relationships (EC4688).",
                severity="high",
                alert_type="Process Anomaly",
                mitre_technique="T1059.003",
                mitre_tactic="Execution",
                event_codes=["4688"],
                match_fn=_process_anomaly,
                owner="Endpoint Defense",
            ),
        ]
        for r in defaults:
            self._rules[r.name] = r

    def load_yaml_rules(self):
        """Loads and updates rules from YAML files in rules_dir."""
        rules_path = Path(self.rules_dir)
        if not rules_path.is_dir():
            return

        for yml_file in rules_path.glob("*.yaml"):
            try:
                data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    continue
                for item in data:
                    name = item.get("name")
                    if not name:
                        continue
                    
                    # Validate against official ATT&CK STIX
                    tech_id = item.get("mitre_technique", "T1059.001")
                    validated = lookup_technique(tech_id)

                    rule = DetectionRule(
                        name=name,
                        description=item.get("description", ""),
                        severity=item.get("severity", "medium"),
                        alert_type=item.get("alert_type", "General Detection"),
                        mitre_technique=validated["technique_id"],
                        mitre_tactic=validated["tactic"],
                        event_codes=item.get("event_codes", []),
                        owner=item.get("owner", "Detection Engineering"),
                        tags=item.get("tags", []),
                        patterns=item.get("patterns", []),
                    )
                    # Bind pattern matcher if not already provided
                    if name in self._rules and self._rules[name].match_fn:
                        rule.match_fn = self._rules[name].match_fn
                    else:
                        rule.match_fn = self._build_yaml_pattern_matcher(rule.patterns)
                    self._rules[name] = rule
            except Exception as e:
                logger.error("yaml_rule_load_error", file=str(yml_file), error=str(e))

    def _build_yaml_pattern_matcher(self, patterns: List[Dict[str, Any]]) -> Callable[[dict], bool]:
        def _match(raw: dict) -> bool:
            if not patterns:
                return False
            for pat in patterns:
                field_val = str(raw.get(pat.get("field", "")) or "").lower()
                any_of = pat.get("any_of", [])
                if not any(term.lower() in field_val for term in any_of):
                    return False
            return True
        return _match

    def list_rules(self) -> List[DetectionRule]:
        return list(self._rules.values())

    def get_rule(self, name: str) -> Optional[DetectionRule]:
        return self._rules.get(name)

    def evaluate_raw_event(self, raw: dict) -> List[DetectionRule]:
        """Matches a raw event against all loaded rules and tracks last_fired timestamps."""
        matched = []
        ec = str(raw.get("EventCode", ""))
        now = datetime.now(timezone.utc)
        for rule in self._rules.values():
            if rule.event_codes and ec not in rule.event_codes:
                continue
            if rule.match_fn and rule.match_fn(raw):
                rule.last_fired = now
                rule.fire_count += 1
                matched.append(rule)
        return matched


detection_engine = DetectionRuleEngine()
