"""Map raw Splunk rows (Sysmon, Windows Security, PowerShell) to CanonicalEvent."""

from __future__ import annotations

from app.normalization.canonical import CanonicalEvent
from app.normalization.clean import (
    basename, clean_value, host_key, merged_fields, parse_hashes,
    parse_ts, raw_event_id, split_account,
)


def _int(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.lower() in ("true", "1", "yes")


def to_canonical(raw: dict) -> CanonicalEvent | None:
    """Return a cleaned event, or None when the row has no usable EventCode or `_time`."""
    fields = merged_fields(raw)
    code = fields.get("EventCode") or fields.get("EventID")
    ts = parse_ts(raw.get("_time"))
    if code is None or ts is None:
        return None

    notes: list[str] = []
    if "EventCode" not in raw or clean_value(raw.get("EventCode")) is None:
        notes.append("event_code_recovered_from_xml_or_eventid")
    recovered = sorted(k for k in fields if clean_value(raw.get(k)) is None and k not in ("EventCode", "EventID"))
    if recovered and raw.get("EventData_Xml"):
        notes.append(f"fields_recovered_from_xml:{len(recovered)}")

    f = fields.get
    host = f("host") or f("Computer") or f("ComputerName")

    image = f("Image") or f("NewProcessName") or f("ProcessName")
    parent = f("ParentImage") or f("ParentProcessName")

    domain, user = split_account(f("User"))
    subject_user = f("SubjectUserName")
    target_user = f("TargetUserName")
    target_domain = f("TargetDomainName")
    user_display = f("User")

    if code in ("4625",):
        user, domain = target_user, target_domain
        user_display = target_user
    elif code in ("4648", "4688", "4624"):
        user, domain = subject_user, f("SubjectDomainName")
        user_display = subject_user

    hashes = parse_hashes(f("Hashes"))

    return CanonicalEvent(
        event_id=raw_event_id(raw),
        ts=ts,
        event_code=code,
        source=str(raw.get("source") or "splunk"),
        host=host,
        host_key=host_key(host),
        user=user,
        user_display=user_display,
        account_domain=domain,
        process=(basename(image) or "").lower() or None,
        process_path=image,
        parent=(basename(parent) or "").lower() or None,
        parent_path=parent,
        command_line=f("CommandLine"),
        hashes=hashes,
        src_ip=f("SourceIp") or f("IpAddress"),
        dst_ip=f("DestinationIp"),
        dst_port=_int(f("DestinationPort")),
        protocol=(f("Protocol") or "").lower() or None,
        initiated=_bool(f("Initiated")),
        query_name=(f("QueryName") or "").lower().rstrip(".") or None,
        query_results=f("QueryResults"),
        registry_key=f("TargetObject"),
        registry_details=f("Details"),
        logon_type=f("LogonType"),
        failure_reason=f("FailureReason") or f("Status"),
        workstation=f("WorkstationName"),
        subject_user=subject_user,
        target_user=target_user,
        target_domain=target_domain,
        script_block=f("ScriptBlockText"),
        fields=fields,
        raw=raw,
        cleaning_notes=notes,
    )
