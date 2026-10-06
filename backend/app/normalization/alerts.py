"""Build the stored alert document from a deduplicated AlertGroup."""

from __future__ import annotations

from datetime import datetime, timezone

from app.normalization.dedup import AlertGroup
from app.normalization.ioc import extract_iocs
from app.normalization.noise import NoiseFilter

MAX_RAW_EVENTS = 20


def _title(group: AlertGroup) -> str:
    rule, ev = group.rule, group.first
    tag = f"[{rule.severity.upper()}]"
    host = ev.host or "Unknown"
    code = ev.event_code
    if code == "1":
        return f"{tag} {rule.alert_type} – {ev.process or '?'} on {host}"
    if code == "3":
        return f"{tag} {rule.alert_type} – {ev.dst_ip or '?'}:{ev.dst_port or '?'} from {host}"
    if code == "13":
        key = (ev.registry_key or "").split("\\")[-1]
        return f"{tag} {rule.alert_type} – {key} on {host}"
    if code == "22":
        return f"{tag} {rule.alert_type} – {ev.query_name or '?'} on {host}"
    if code == "4625":
        return f"{tag} {rule.alert_type} – {group.count} failures from {ev.src_ip or ev.workstation or '?'}"
    if code == "4648":
        return f"{tag} {rule.alert_type} – {ev.subject_user or '?'} → {ev.target_user or '?'}"
    if code == "4688":
        return f"{tag} {rule.alert_type} – {ev.parent or '?'} → {ev.process or '?'} on {host}"
    if code == "4104":
        return f"{tag} {rule.alert_type} – Script Block on {host}"
    return f"{tag} {rule.alert_type} on {host}"


def build_alert_doc(group: AlertGroup, org_id: str, noise: NoiseFilter | None = None) -> dict:
    ev, rule = group.first, group.rule
    benign = noise.is_benign_domain if noise else None

    iocs: list[str] = []
    for event in group.events:
        for ioc in extract_iocs(event, is_benign_domain=benign):
            if ioc not in iocs:
                iocs.append(ioc)

    notes: list[str] = []
    for event in group.events:
        for note in event.cleaning_notes:
            if note not in notes:
                notes.append(note)

    return {
        "_id": group.alert_id,
        "org_id": org_id,
        "title": _title(group),
        "description": rule.description,
        "severity": rule.severity,
        "alert_type": rule.alert_type,
        "rule_name": rule.name,
        "mitre_technique": rule.mitre_technique,
        "mitre_tactic": rule.mitre_tactic,
        "host": ev.host or "Unknown",
        "user": ev.user_display or ev.user or "Unknown",
        "status": "New",
        "ai_confidence": 0,
        "source_siem": "splunk",
        "event_code": ev.event_code,
        "created_at": group.first_seen,
        "first_seen": group.first_seen,
        "last_seen": group.last_seen,
        "count": group.count,
        "detected_at": datetime.now(timezone.utc),
        "extracted_iocs": iocs,
        "process_name": ev.process_path.split("\\")[-1] if ev.process_path else None,
        "command_line": ev.command_line or ev.script_block,
        "parent_process": ev.parent_path.split("\\")[-1] if ev.parent_path else None,
        "source_ip": ev.src_ip,
        "dest_ip": ev.dst_ip,
        "dest_port": str(ev.dst_port) if ev.dst_port is not None else None,
        "protocol": ev.protocol,
        "registry_key": ev.registry_key,
        "registry_details": ev.registry_details,
        "dns_query": ev.query_name,
        "hashes": ev.fields.get("Hashes"),
        "logon_type": ev.logon_type,
        "failure_reason": ev.failure_reason,
        "event_ids": [e.event_id for e in group.events],
        "raw_event": ev.raw,
        "raw_events": [e.raw for e in group.events[:MAX_RAW_EVENTS]],
        "cleaning_notes": notes,
    }
