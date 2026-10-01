"""
Unit tests for MITRE ATT&CK Mapping Agent Node.
"""

import pytest
from app.agents.mitre_agent import map_mitre_node


def test_mitre_explicit_technique():
    state = {
        "alert_data": {
            "_id": "alert-test-1",
            "mitre_technique": "T1059.001",
            "rule_name": "Suspicious_PowerShell",
        },
        "context": {},
        "investigation_log": [],
    }
    result = map_mitre_node(state)
    mappings = result["mitre_mappings"]
    
    assert len(mappings) >= 1
    tech_ids = [m["technique_id"] for m in mappings]
    assert "T1059.001" in tech_ids
    
    ps_entry = next(m for m in mappings if m["technique_id"] == "T1059.001")
    assert ps_entry["tactic"] == "Execution"
    assert "PowerShell" in ps_entry["name"]
    assert "https://attack.mitre.org/techniques/T1059/001/" == ps_entry["url"]
    assert "Explicitly flagged" in ps_entry["evidence"]
    assert any("MITRE ATT&CK Agent" in log for log in result["investigation_log"])


def test_mitre_powershell_obfuscation_heuristics():
    state = {
        "alert_data": {
            "_id": "alert-test-2",
            "raw_event": {"EventCode": "1"},
        },
        "context": {
            "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        },
        "investigation_log": [],
    }
    result = map_mitre_node(state)
    mappings = result["mitre_mappings"]
    tech_ids = [m["technique_id"] for m in mappings]
    
    # Expect both PowerShell execution and Deobfuscation
    assert "T1059.001" in tech_ids
    assert "T1140" in tech_ids


def test_mitre_registry_persistence_heuristics():
    state = {
        "alert_data": {
            "_id": "alert-test-3",
            "raw_event": {"EventCode": "13", "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"},
        },
        "context": {
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        },
        "investigation_log": [],
    }
    result = map_mitre_node(state)
    mappings = result["mitre_mappings"]
    tech_ids = [m["technique_id"] for m in mappings]
    
    assert "T1547.001" in tech_ids
    reg_entry = next(m for m in mappings if m["technique_id"] == "T1547.001")
    assert reg_entry["tactic"] == "Persistence"


def test_mitre_failed_logon_brute_force():
    state = {
        "alert_data": {
            "_id": "alert-test-4",
            "event_code": "4625",
            "raw_event": {"EventCode": "4625", "TargetUserName": "Administrator"},
        },
        "context": {},
        "investigation_log": [],
    }
    result = map_mitre_node(state)
    mappings = result["mitre_mappings"]
    tech_ids = [m["technique_id"] for m in mappings]
    
    assert "T1110.001" in tech_ids
    bf_entry = next(m for m in mappings if m["technique_id"] == "T1110.001")
    assert bf_entry["tactic"] == "Credential Access"


def test_mitre_discovery_reconnaissance():
    state = {
        "alert_data": {
            "_id": "alert-test-5",
            "raw_event": {"EventCode": "1"},
        },
        "context": {
            "process_name": "whoami.exe",
            "command_line": "net.exe group \"Domain Admins\" /domain",
        },
        "investigation_log": [],
    }
    result = map_mitre_node(state)
    mappings = result["mitre_mappings"]
    tech_ids = [m["technique_id"] for m in mappings]
    
    assert "T1082" in tech_ids
    assert "T1087" in tech_ids
