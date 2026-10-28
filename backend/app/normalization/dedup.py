"""Collapse repeated detections into one alert and derive deterministic fingerprint IDs."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.normalization.canonical import CanonicalEvent

MAX_GROUP_EVENTS = 50


@dataclass
class RuleHit:
    rule: Any
    event: CanonicalEvent
    count: int = 1


@dataclass
class AlertGroup:
    alert_id: str
    rule: Any
    first: CanonicalEvent
    count: int
    first_seen: datetime
    last_seen: datetime
    events: list[CanonicalEvent] = field(default_factory=list)


def stable_id(*parts: object) -> str:
    """Calculates deterministic SHA-256 fingerprint for deduplication."""
    material = "\x1f".join("" if p is None else str(p).strip().lower() for p in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _utc(ts: datetime) -> datetime:
    """Treat naive datetimes as UTC so IDs do not depend on the local zone."""
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts


def _bucket(ts: datetime, bucket_seconds: int) -> int:
    return int(_utc(ts).timestamp()) // bucket_seconds


def _entity_key(ev: CanonicalEvent) -> tuple:
    """Normalized fields that define 'the same detection' for each event type across ingestion cycles."""
    code = ev.event_code
    if code in ("1", "4688"):
        cmd_clean = " ".join((ev.command_line or "").lower().split())
        return (ev.process or "", cmd_clean)
    if code == "3":
        return (ev.process or "", ev.dst_ip or "", str(ev.dst_port or 0))
    if code == "13":
        return ((ev.registry_key or "").lower(),)
    if code == "22":
        return (ev.process or "", (ev.query_name or "").lower())
    if code == "4104":
        return (hashlib.sha256((ev.script_block or "").strip().encode("utf-8")).hexdigest()[:16],)
    if code == "4648":
        return (ev.subject_user or "", ev.target_user or "")
    if code == "4625":
        return (ev.src_ip or ev.workstation or "unknown",)
    return (ev.event_id or "",)


def group_hits(hits: Iterable[RuleHit], org_id: str, bucket_seconds: int) -> list[AlertGroup]:
    """
    Groups hits using deterministic fingerprinting.
    Includes rule name, host_key, target user, time bucket, and core entity keys.
    Prevents duplicates even when polling cycles overlap.
    """
    groups: dict[str, AlertGroup] = {}
    for hit in hits:
        ev = hit.event
        ts = _utc(ev.ts)
        bucket = _bucket(ts, bucket_seconds)
        user = None if ev.event_code == "4625" else ev.user
        
        # Build deterministic fingerprint
        alert_id = stable_id(
            org_id,
            hit.rule.name,
            ev.host_key,
            user,
            bucket,
            *_entity_key(ev),
        )
        
        group = groups.get(alert_id)
        if group is None:
            groups[alert_id] = AlertGroup(
                alert_id=alert_id,
                rule=hit.rule,
                first=ev,
                count=hit.count,
                first_seen=ts,
                last_seen=ts,
                events=[ev],
            )
            continue
        group.count += hit.count
        if ts < group.first_seen:
            group.first_seen, group.first = ts, ev
        group.last_seen = max(group.last_seen, ts)
        if len(group.events) < MAX_GROUP_EVENTS:
            group.events.append(ev)
    return list(groups.values())


def aggregate_failed_logons(
    events: Iterable[CanonicalEvent], threshold: int, bucket_seconds: int,
) -> list[tuple[CanonicalEvent, int]]:
    """One (representative event, failure count) per (source, host, bucket) with count >= threshold."""
    buckets: dict[tuple, list[CanonicalEvent]] = defaultdict(list)
    for ev in events:
        if ev.event_code != "4625":
            continue
        source = ev.src_ip or ev.workstation or "unknown"
        buckets[(source, ev.host_key, _bucket(ev.ts, bucket_seconds))].append(ev)
    result = []
    for items in buckets.values():
        if len(items) >= threshold:
            items.sort(key=lambda e: (_utc(e.ts), e.event_id))
            result.append((items[0], len(items)))
    return result
