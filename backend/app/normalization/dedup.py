"""Collapse repeated detections into one alert and derive stable IDs."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

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
    material = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _utc(ts: datetime) -> datetime:
    """Treat naive datetimes as UTC so IDs do not depend on the local zone."""
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts


def _bucket(ts: datetime, bucket_seconds: int) -> int:
    return int(_utc(ts).timestamp()) // bucket_seconds


def _entity_key(ev: CanonicalEvent) -> tuple:
    """Fields that define 'the same detection' for each event type."""
    code = ev.event_code
    if code in ("1", "4688"):
        return (ev.process, ev.command_line)
    if code == "3":
        return (ev.process, ev.dst_ip, ev.dst_port)
    if code == "13":
        return (ev.registry_key,)
    if code == "22":
        return (ev.process, ev.query_name)
    if code == "4104":
        return (hashlib.sha256((ev.script_block or "").encode()).hexdigest(),)
    if code == "4648":
        return (ev.subject_user, ev.target_user)
    if code == "4625":
        return (ev.src_ip or ev.workstation or "unknown",)
    return (ev.event_id,)


def group_hits(hits: Iterable[RuleHit], org_id: str, bucket_seconds: int) -> list[AlertGroup]:
    groups: dict[str, AlertGroup] = {}
    for hit in hits:
        ev = hit.event
        ts = _utc(ev.ts)
        bucket = _bucket(ts, bucket_seconds)
        user = None if ev.event_code == "4625" else ev.user
        alert_id = stable_id(org_id, hit.rule.name, ev.host_key, user, bucket, *_entity_key(ev))
        group = groups.get(alert_id)
        if group is None:
            groups[alert_id] = AlertGroup(
                alert_id=alert_id, rule=hit.rule, first=ev, count=hit.count,
                first_seen=ts, last_seen=ts, events=[ev],
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
