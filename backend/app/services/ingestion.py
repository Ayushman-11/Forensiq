"""
IngestionService – pulls real telemetry events from Splunk using detection rules,
normalises them into Forensiq alert documents, and stores them in MongoDB.

Key design decisions:
  - Incremental polling: tracks last_ingested_time in `ingestion_state` collection
  - Deterministic _id: SHA-256 of Splunk's _cd (bucket:event offset) field
  - Zero mock data: all field values come from actual Splunk event payloads
  - IOC extraction: IPs, domains and file hashes are parsed from raw fields
  - Deduplication: skips events already in MongoDB before inserting
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.logging import logger
from app.infrastructure.siem.splunk import SplunkClient
from app.services.detection_rules import DetectionRule, DetectionRuleEngine

# ---------------------------------------------------------------------------
# IOC helpers
# ---------------------------------------------------------------------------

_PRIVATE_IP_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|\:\:1)"
)
_IPV4_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b"
)
_HASH_RE = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
# Simple domain heuristic — avoid matching plain hostnames like "AYUSH"
_DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9-]{1,63}\.){2,}(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|xyz|top|info|biz|me|us|cloud|ai|app|dev))\b"
)


def _is_private(ip: str) -> bool:
    return bool(_PRIVATE_IP_RE.match(ip))


def extract_iocs(raw: dict) -> List[str]:
    """
    Extract unique, non-private IOCs from a raw Splunk event.
    Returns a deduplicated list of strings (IPs, domains, hashes).
    """
    seen: set = set()
    iocs: List[str] = []

    def _add(val: str) -> None:
        if val and val not in seen:
            seen.add(val)
            iocs.append(val)

    # --- IPs from named fields -------------------------------------------------
    for field in ("DestinationIp", "SourceIp", "IpAddress"):
        ip = str(raw.get(field) or "").strip()
        if ip and ip not in ("-", "") and not _is_private(ip):
            _add(ip)

    # --- Domains from DNS query field ------------------------------------------
    qname = str(raw.get("QueryName") or "").strip()
    if qname and qname not in ("-", ""):
        _add(qname)

    # --- QueryResults: may contain semicolon-separated IPs --------------------
    qresults = str(raw.get("QueryResults") or "")
    for part in qresults.split(";"):
        part = part.strip()
        # strip IPv6-mapped-IPv4 prefix
        if part.startswith("::ffff:"):
            part = part[7:]
        m = _IPV4_RE.match(part)
        if m and not _is_private(m.group(1)):
            _add(m.group(1))

    # --- Hashes from Sysmon Hashes field (MD5=...,SHA256=...) -----------------
    hashes_field = str(raw.get("Hashes") or "")
    for segment in hashes_field.split(","):
        if "=" in segment:
            hash_val = segment.split("=", 1)[1].strip()
            if _HASH_RE.fullmatch(hash_val):
                _add(hash_val)

    # --- Fallback: scan CommandLine for embedded IPs --------------------------
    for field in ("CommandLine", "ParentCommandLine", "ScriptBlockText"):
        text = str(raw.get(field) or "")
        for m in _IPV4_RE.finditer(text):
            ip = m.group(1)
            if not _is_private(ip):
                _add(ip)
        for m in _DOMAIN_RE.finditer(text):
            _add(m.group(1))

    return iocs


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _parse_ts(raw: dict) -> datetime:
    raw_time = raw.get("_time", "")
    try:
        return datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _event_id(raw: dict) -> str:
    """Deterministic ID from Splunk's _cd field (bucket:offset) or fallback."""
    cd = raw.get("_cd") or raw.get("_bkt", "") + "_" + str(raw.get("_serial", ""))
    return hashlib.sha256(cd.encode()).hexdigest()[:32]


def _title_for(rule: DetectionRule, raw: dict) -> str:
    """Build a human-readable alert title from the rule + key event fields."""
    severity_tag = f"[{rule.severity.upper()}]"
    host = raw.get("host") or raw.get("Computer") or "Unknown"

    ec = str(raw.get("EventCode", ""))
    if ec == "1":
        proc = raw.get("Image", "").split("\\")[-1]
        return f"{severity_tag} {rule.alert_type} – {proc} on {host}"
    if ec == "3":
        dest = raw.get("DestinationIp", "?")
        port = raw.get("DestinationPort", "?")
        return f"{severity_tag} {rule.alert_type} – {dest}:{port} from {host}"
    if ec == "13":
        key = (raw.get("TargetObject") or "").split("\\")[-1]
        return f"{severity_tag} {rule.alert_type} – {key} on {host}"
    if ec == "22":
        return f"{severity_tag} {rule.alert_type} – {raw.get('QueryName', '?')} on {host}"
    if ec == "4625":
        return f"{severity_tag} {rule.alert_type} – {raw.get('TargetUserName', '?')} from {raw.get('IpAddress', '?')}"
    if ec == "4648":
        return f"{severity_tag} {rule.alert_type} – {raw.get('SubjectUserName', '?')} → {raw.get('TargetUserName', '?')}"
    if ec == "4688":
        proc = (raw.get("NewProcessName") or "").split("\\")[-1]
        parent = (raw.get("ParentProcessName") or "").split("\\")[-1]
        return f"{severity_tag} {rule.alert_type} – {parent} → {proc} on {host}"
    if ec == "4104":
        return f"{severity_tag} {rule.alert_type} – Script Block on {host}"
    # Brute-force aggregate row
    ip = raw.get("IpAddress") or raw.get("SourceIp", "?")
    count = raw.get("count", "?")
    return f"{severity_tag} {rule.alert_type} – {count} failures from {ip}"


def normalize_event(raw: dict, rule: DetectionRule) -> dict:
    """Convert a raw Splunk result dict + matched rule into a Forensiq alert doc."""
    ec = str(raw.get("EventCode", ""))
    host = str(raw.get("host") or raw.get("Computer") or "Unknown")
    user = str(
        raw.get("User")
        or raw.get("SubjectUserName")
        or raw.get("TargetUserName")
        or "Unknown"
    )
    ts = _parse_ts(raw)

    doc: Dict = {
        "_id": _event_id(raw),
        "title": _title_for(rule, raw),
        "description": rule.description,
        "severity": rule.severity,
        "alert_type": rule.alert_type,
        "rule_name": rule.name,
        "mitre_technique": rule.mitre_technique,
        "mitre_tactic": rule.mitre_tactic,
        "host": host,
        "user": user,
        "status": "New",
        "ai_confidence": 0,
        "source_siem": "splunk",
        "event_code": ec,
        "created_at": ts,
        "detected_at": datetime.now(timezone.utc),
        "extracted_iocs": extract_iocs(raw),
        # Per-event-type fields
        "process_name": (raw.get("Image") or raw.get("NewProcessName") or "").split("\\")[-1] or None,
        "command_line": raw.get("CommandLine") or raw.get("ScriptBlockText") or None,
        "parent_process": (raw.get("ParentImage") or raw.get("ParentProcessName") or "").split("\\")[-1] or None,
        "source_ip": raw.get("SourceIp") or None,
        "dest_ip": raw.get("DestinationIp") or None,
        "dest_port": raw.get("DestinationPort") or None,
        "protocol": raw.get("Protocol") or None,
        "registry_key": raw.get("TargetObject") or None,
        "registry_details": raw.get("Details") or None,
        "dns_query": raw.get("QueryName") or None,
        "hashes": raw.get("Hashes") or None,
        "logon_type": raw.get("LogonType") or None,
        "failure_reason": raw.get("FailureReason") or None,
        "raw_event": {k: v for k, v in raw.items() if not k.startswith("_")},
    }
    return doc


# ---------------------------------------------------------------------------
# IngestionService
# ---------------------------------------------------------------------------

class IngestionService:
    """
    Runs each DetectionRule's SPL query against Splunk, normalises the results
    into Forensiq alert documents, deduplicates against MongoDB, and persists
    new alerts.  Tracks the last ingestion timestamp for incremental polling.
    """

    STATE_COLLECTION = "ingestion_state"
    ALERTS_COLLECTION = "alerts"

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.engine = DetectionRuleEngine()

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    async def _get_last_ingested_time(self) -> str:
        doc = await self.db[self.STATE_COLLECTION].find_one({"_id": "last_ingested"})
        if doc and doc.get("ts"):
            return doc["ts"]
        return "-7d"  # first run: look back 7 days

    async def _update_last_ingested_time(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        await self.db[self.STATE_COLLECTION].update_one(
            {"_id": "last_ingested"},
            {"$set": {"ts": now_iso}},
            upsert=True,
        )

    # ------------------------------------------------------------------
    # Main ingestion method
    # ------------------------------------------------------------------

    async def fetch_and_store_alerts(self, limit: int = 100) -> List[dict]:
        """
        For each detection rule:
          1. Run its SPL query against Splunk (from last_ingested_time)
          2. Evaluate each result event against the rule's match_fn
          3. Normalise matching events into alert docs
          4. Deduplicate and insert into MongoDB
        Returns the list of newly inserted alert documents.
        """
        earliest = await self._get_last_ingested_time()
        rules = self.engine.get_all_rules()
        new_alerts: List[dict] = []
        total_fetched = 0

        splunk = SplunkClient()
        try:
            for rule in rules:
                try:
                    logger.info(
                        "ingestion_rule_start",
                        rule=rule.name,
                        earliest=earliest,
                    )
                    raw_events = await splunk.search(
                        query=rule.spl_query,
                        earliest_time=earliest,
                        latest_time="now",
                        limit=limit,
                    )
                    total_fetched += len(raw_events)

                    for norm_event in raw_events:
                        # norm_event is a NormalizedEvent; grab the raw_payload dict
                        raw = norm_event.raw_payload if hasattr(norm_event, "raw_payload") else {}
                        if not raw:
                            continue

                        # Validate against local match_fn (belt-and-suspenders)
                        if rule.match_fn and not rule.match_fn(raw):
                            continue

                        alert_doc = normalize_event(raw, rule)
                        alert_id = alert_doc["_id"]

                        # Deduplication check
                        existing = await self.db[self.ALERTS_COLLECTION].find_one(
                            {"_id": alert_id}, {"_id": 1}
                        )
                        if existing:
                            continue

                        await self.db[self.ALERTS_COLLECTION].insert_one(alert_doc)
                        new_alerts.append(alert_doc)

                    logger.info(
                        "ingestion_rule_complete",
                        rule=rule.name,
                        fetched=len(raw_events),
                        inserted=len([a for a in new_alerts if a.get("rule_name") == rule.name]),
                    )

                except Exception as rule_err:
                    # Never abort the whole pipeline for a single rule failure
                    logger.error(
                        "ingestion_rule_error",
                        rule=rule.name,
                        error=str(rule_err),
                    )
                    continue

        finally:
            await splunk.close()

        await self._update_last_ingested_time()

        logger.info(
            "ingestion_complete",
            total_fetched=total_fetched,
            total_inserted=len(new_alerts),
            rules_run=len(rules),
        )
        return new_alerts
