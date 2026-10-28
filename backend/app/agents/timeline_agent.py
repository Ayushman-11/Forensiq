"""
Timeline Agent Node for LangGraph.
Assembles, normalizes, and chronologically orders multi-source security events into
an end-to-end attack timeline grouped by MITRE attack phases.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import re
from app.core.logging import logger
from app.agents.state import AgentState

# Standard SOC Attack Phase Definitions
PHASE_RECON = "Reconnaissance & Discovery"
PHASE_EXECUTION = "Initial Access & Execution"
PHASE_PERSISTENCE = "Persistence & Privilege Escalation"
PHASE_LATERAL = "Lateral Movement & Credential Access"
PHASE_C2 = "Command and Control & Exfiltration"


def _determine_phase(text: str, tactic: Optional[str] = None) -> str:
    """Classifies an event into a standardized MITRE attack phase."""
    if tactic:
        t = tactic.lower()
        if "recon" in t or "discovery" in t:
            return PHASE_RECON
        if "execution" in t or "initial" in t:
            return PHASE_EXECUTION
        if "persistence" in t or "privilege" in t or "escalation" in t:
            return PHASE_PERSISTENCE
        if "credential" in t or "lateral" in t:
            return PHASE_LATERAL
        if "command" in t or "c2" in t or "exfiltration" in t:
            return PHASE_C2

    s = (text or "").lower()
    if any(k in s for k in ("port scan", "whoami", "discovery", "recon", "net user", "ipconfig")):
        return PHASE_RECON
    if any(k in s for k in ("powershell", "cmd.exe", "process", "execution", "script", "wmic")):
        return PHASE_EXECUTION
    if any(k in s for k in ("run", "runonce", "registry", "service", "schtasks", "scheduled task", "autostart")):
        return PHASE_PERSISTENCE
    if any(k in s for k in ("rdp", "smb", "brute force", "failed login", "logon", "4625", "credential", "mimikatz")):
        return PHASE_LATERAL
    if any(k in s for k in ("beacon", "http", "outbound", "c2", "dns", "traffic", "download")):
        return PHASE_C2

    return PHASE_EXECUTION


def _parse_iso(ts: Any) -> datetime:
    """Robustly parse timestamps into timezone-aware datetimes."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if not ts or not isinstance(ts, str):
        return datetime.now(timezone.utc)
    try:
        clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return datetime.now(timezone.utc)


def build_timeline_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Assembles a chronological, phase-tagged attack timeline from:
      1. Primary alert event
      2. Process and telemetry context (parent/child execution, network, registry)
      3. Correlated historical alerts from the correlation agent
      4. Flagged malicious / suspicious IOC discoveries
    """
    alert = state.get("alert_data", {})
    context = state.get("context", {})
    correlations = state.get("correlations", [])
    enrichments = state.get("enrichment_results", [])
    mitre_mappings = state.get("mitre_mappings", [])
    current_log = state.get("investigation_log", [])

    alert_id = str(alert.get("_id", "unknown"))
    logger.info("timeline_node_start", alert_id=alert_id)

    raw_events: List[Dict[str, Any]] = []

    # 1. Primary Alert Event
    primary_ts = alert.get("created_at") or datetime.now(timezone.utc).isoformat()
    primary_dt = _parse_iso(primary_ts)
    primary_title = alert.get("title", "Security Alert Triggered")
    primary_tactic = alert.get("mitre_tactic") or (mitre_mappings[0]["tactic"] if mitre_mappings else None)

    raw_events.append({
        "timestamp": primary_dt.isoformat(),
        "_dt": primary_dt,
        "phase": _determine_phase(primary_title, primary_tactic),
        "event_type": alert.get("alert_type") or "SIEM Detection",
        "description": f"{primary_title} on host {alert.get('host', 'unknown')}",
        "source": alert.get("source_siem", "Splunk"),
        "severity": str(alert.get("severity", "medium")).lower(),
    })

    # 2. Process Telemetry Context
    process_name = context.get("process_name") or alert.get("process_name")
    parent_process = context.get("parent_process") or alert.get("parent_process")
    command_line = context.get("command_line") or alert.get("command_line")

    if parent_process and process_name:
        raw_events.append({
            "timestamp": primary_dt.isoformat(),
            "_dt": primary_dt,
            "phase": PHASE_EXECUTION,
            "event_type": "Process Tree",
            "description": f"Parent process '{parent_process}' spawned target process '{process_name}'",
            "source": "Sysmon EventCode 1",
            "severity": "info",
        })

    if command_line and ("-enc" in command_line.lower() or "bypass" in command_line.lower() or "whoami" in command_line.lower()):
        raw_events.append({
            "timestamp": primary_dt.isoformat(),
            "_dt": primary_dt,
            "phase": _determine_phase(command_line),
            "event_type": "Command Execution",
            "description": f"Executed command: {command_line[:120]}{'...' if len(command_line) > 120 else ''}",
            "source": "Process CommandLine",
            "severity": "high",
        })

    # Network Connection Context
    dest_ip = context.get("dest_ip") or alert.get("dest_ip")
    dest_port = context.get("dest_port") or alert.get("dest_port")
    if dest_ip:
        raw_events.append({
            "timestamp": primary_dt.isoformat(),
            "_dt": primary_dt,
            "phase": PHASE_C2 if str(dest_port) in ("80", "443", "8080", "8443") else PHASE_LATERAL,
            "event_type": "Network Connection",
            "description": f"Network session established to {dest_ip}:{dest_port or '?'}",
            "source": "Sysmon EventCode 3",
            "severity": "medium",
        })

    # Registry Modification Context
    registry_key = context.get("registry_key") or alert.get("registry_key")
    if registry_key:
        raw_events.append({
            "timestamp": primary_dt.isoformat(),
            "_dt": primary_dt,
            "phase": PHASE_PERSISTENCE,
            "event_type": "Registry Modification",
            "description": f"Persistence registry key modified: {registry_key}",
            "source": "Sysmon EventCode 13",
            "severity": "high",
        })

    # 3. Correlated Historical Alerts
    for corr in correlations:
        corr_ts = corr.get("created_at")
        corr_dt = _parse_iso(corr_ts)
        corr_title = corr.get("title", "Related Event")
        corr_host = corr.get("host") or alert.get("host", "target host")

        # Determine match reason
        match_types = [m.get("type", "") for m in corr.get("matches", [])]
        match_str = f" (matched on {', '.join(match_types)})" if match_types else ""

        raw_events.append({
            "timestamp": corr_dt.isoformat(),
            "_dt": corr_dt,
            "phase": _determine_phase(corr_title),
            "event_type": "Correlated Alert",
            "description": f"Prior alert '{corr_title}' on {corr_host}{match_str}",
            "source": "Forensiq Correlation",
            "severity": str(corr.get("severity", "medium")).lower(),
        })

    # 4. Enriched Threat Intel Findings
    for enr in enrichments:
        if enr.get("reputation") in ("malicious", "suspicious"):
            raw_events.append({
                "timestamp": primary_dt.isoformat(),
                "_dt": primary_dt,
                "phase": PHASE_C2 if enr.get("ioc_type") in ("ip", "domain") else PHASE_EXECUTION,
                "event_type": "Threat Intel Flag",
                "description": f"IOC {enr.get('ioc')} flagged as {enr.get('reputation').upper()} by {enr.get('source')} (Score: {enr.get('threat_score')}/100)",
                "source": enr.get("source", "ThreatIntel"),
                "severity": "critical" if enr.get("reputation") == "malicious" else "high",
            })

    # 5. Sort chronologically (oldest to newest)
    raw_events.sort(key=lambda x: x["_dt"])

    # 6. Deduplicate by (timestamp, description)
    seen_keys = set()
    timeline: List[Dict[str, Any]] = []
    for item in raw_events:
        dedup_key = (item["timestamp"], item["description"])
        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            # Remove internal sort helper
            item.pop("_dt", None)
            timeline.append(item)

    # 7. Summary for investigation log
    distinct_phases = sorted(set(e["phase"] for e in timeline))
    log_entry = (
        f"Timeline Agent: assembled {len(timeline)} attack sequence event(s) "
        f"spanning {len(distinct_phases)} phase(s) ({', '.join(distinct_phases)})"
    )

    logger.info("timeline_node_complete",
                alert_id=alert_id,
                events_count=len(timeline),
                phases_count=len(distinct_phases))

    new_log = current_log + [log_entry]

    return {
        "timeline": timeline,
        "investigation_log": new_log
    }
