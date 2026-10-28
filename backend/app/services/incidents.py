"""
Incident grouping: related alerts become one case an analyst can work.

An alert joins an open incident when it shares a link key with it and falls within the time
window of the incident's span. Link keys, strongest first:

- host: the machine the detection fired on.
- user: a real account. Machine accounts, built-in service identities and default privileged
  names (Administrator, root) are never keys: they are on every host, so they would fuse unrelated work.
- hash / domain: a file hash is specific to one binary. A domain links only when it is not
  shared hosting or benign (see config/noise.yaml): everyone reaches github.com, so it proves nothing.

IP addresses are deliberately not keys: CDN and cloud addresses are shared by unrelated traffic.

One code path (`link_alert`) serves live ingestion and `rebuild_incidents`, so a rebuild reproduces
what ingestion would have produced. Incident state is derived from member alerts at read time
(there is no separate incident status to drift out of sync).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from app.core.config import settings
from app.normalization.noise import NoiseFilter
from app.services.triage import OPEN_STATUSES

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


async def update_incident_counters(db, incident_id: str) -> None:
    """Computes and stores open/closed counters, state and assignees directly on the incident document."""
    if not incident_id:
        return
    pipeline = [
        {"$match": {"incident_id": incident_id}},
        {"$group": {
            "_id": "$status",
            "count": {"$sum": 1},
            "unassigned_open": {
                "$sum": {
                    "$cond": [
                        {"$and": [
                            {"$in": ["$status", list(OPEN_STATUSES)]},
                            {"$or": [{"$eq": ["$assignee_id", None]}, {"$eq": ["$assignee_id", ""]}]}
                        ]},
                        1, 0
                    ]
                }
            },
            "owners": {
                "$addToSet": {
                    "$cond": [
                        {"$and": [{"$in": ["$status", list(OPEN_STATUSES)]}, {"$ne": ["$assignee_email", None]}]},
                        "$assignee_email",
                        None
                    ]
                }
            }
        }}
    ]
    by_status: dict[str, int] = {}
    unassigned_open = 0
    owners: set[str] = set()
    async for doc in db["alerts"].aggregate(pipeline):
        st = doc["_id"] or "New"
        by_status[st] = doc["count"]
        unassigned_open += doc.get("unassigned_open", 0)
        for o in doc.get("owners", []):
            if o:
                owners.add(o)

    open_count = sum(cnt for st, cnt in by_status.items() if st in OPEN_STATUSES)
    total_count = sum(by_status.values())
    state = "open" if open_count > 0 else "resolved"
    owner = next(iter(owners)) if len(owners) == 1 and not unassigned_open else None
    mixed_owners = len(owners) > 1 or (len(owners) == 1 and unassigned_open > 0)

    inc = await db["incidents"].find_one({"_id": incident_id}, {"severity": 1})
    sev = inc.get("severity", "low") if inc else "low"
    sev_rank = SEVERITY_RANK.get(sev, 1)

    await db["incidents"].update_one(
        {"_id": incident_id},
        {"$set": {
            "status_counts": by_status,
            "open_count": open_count,
            "alert_count": total_count,
            "unassigned_open": unassigned_open,
            "owner": owner,
            "mixed_owners": mixed_owners,
            "state": state,
            "severity_rank": sev_rank,
            "updated_at": datetime.now(timezone.utc),
        }}
    )

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_GENERIC_USER_RE = re.compile(
    r"^(?:unknown|-|n/a|none|system|local service|network service|anonymous logon|window manager\\.*|font driver host\\.*"
    r"|(?:.*\\)?(?:administrator|admin|root|guest|defaultaccount|nt authority\\.*)|.*\$)$",
    re.I,
)


def _naive_utc(value) -> Optional[datetime]:
    """Mongo returns naive UTC datetimes; normalise everything to that so comparisons never mix kinds."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def alert_time(alert: dict) -> Optional[datetime]:
    """Event time drives the window: backfilled history must group by when it happened."""
    return _naive_utc(alert.get("first_seen")) or _naive_utc(alert.get("created_at")) or _naive_utc(alert.get("detected_at"))


def link_keys(alert: dict, noise: Optional[NoiseFilter] = None) -> list[str]:
    keys: list[str] = []
    host = str(alert.get("host") or "").strip().lower()
    if host and host != "unknown":
        keys.append(f"host:{host}")
    user = str(alert.get("user") or "").strip().lower()
    if user and not _GENERIC_USER_RE.match(user):
        keys.append(f"user:{user}")
    for ioc in alert.get("extracted_iocs") or []:
        value = str(ioc or "").strip().lower()
        if not value:
            continue
        if _HASH_RE.match(value):
            keys.append(f"hash:{value}")
        elif not _IPV4_RE.match(value) and ":" not in value and "." in value:
            if noise and (noise.is_shared_hosting(value) or noise.is_benign_domain(value)):
                continue
            keys.append(f"domain:{value}")
    return list(dict.fromkeys(keys))


def _window() -> timedelta:
    return timedelta(hours=settings.INCIDENT_WINDOW_HOURS)


async def link_alert(db, alert: dict, noise: Optional[NoiseFilter] = None) -> Optional[str]:
    """Attach one alert to an incident (creating or merging as needed). Returns the incident id."""
    when = alert_time(alert)
    keys = link_keys(alert, noise)
    if when is None or not keys:
        return None
    org = alert.get("org_id", "default")
    window = _window()

    candidates = []
    cursor = db["incidents"].find({
        "org_id": org,
        "keys": {"$in": keys},
        "last_seen": {"$gte": when - window},
        "first_seen": {"$lte": when + window},
    }).sort("first_seen", 1)
    async for incident in cursor:
        candidates.append(incident)

    severity = str(alert.get("severity") or "low").lower()
    alert_id = alert["_id"]
    fields = {
        "hosts": [alert["host"]] if alert.get("host") and alert["host"] != "Unknown" else [],
        "users": [alert["user"]] if alert.get("user") and alert["user"] != "Unknown" else [],
        "rules": [alert["rule_name"]] if alert.get("rule_name") else [],
    }

    status = alert.get("status", "New")
    is_open = 1 if status in OPEN_STATUSES else 0
    sev_rank = SEVERITY_RANK.get(severity, 1)

    if not candidates:
        incident_id = str(uuid.uuid4())
        await db["incidents"].insert_one({
            "_id": incident_id, "org_id": org, "keys": keys, "first_seen": when, "last_seen": when,
            "severity": severity, "severity_rank": sev_rank, "alert_count": 1, "open_count": is_open,
            "status_counts": {status: 1}, "state": "open" if is_open else "resolved",
            "unassigned_open": is_open if not alert.get("assignee_id") else 0,
            "owner": alert.get("assignee_email") if is_open and alert.get("assignee_email") else None,
            "created_at": datetime.now(timezone.utc),
            **fields,
        })
    else:
        survivor, absorbed = candidates[0], candidates[1:]
        incident_id = survivor["_id"]
        merged_keys = set(keys) | set(survivor.get("keys", []))
        merged = {name: set(survivor.get(name, [])) | set(values) for name, values in fields.items()}
        first_seen = min(survivor["first_seen"], when)
        last_seen = max(survivor["last_seen"], when)
        count = survivor.get("alert_count", 0) + 1
        top = max([survivor.get("severity", "low"), severity], key=lambda s: SEVERITY_RANK.get(s, 0))
        for other in absorbed:
            merged_keys |= set(other.get("keys", []))
            for name in merged:
                merged[name] |= set(other.get(name, []))
            first_seen = min(first_seen, other["first_seen"])
            last_seen = max(last_seen, other["last_seen"])
            count += other.get("alert_count", 0)
            top = max([top, other.get("severity", "low")], key=lambda s: SEVERITY_RANK.get(s, 0))
            await db["alerts"].update_many({"org_id": org, "incident_id": other["_id"]}, {"$set": {"incident_id": incident_id}})
            await db["incidents"].delete_one({"_id": other["_id"]})
        await db["incidents"].update_one({"_id": incident_id}, {"$set": {
            "keys": sorted(merged_keys), "first_seen": first_seen, "last_seen": last_seen,
            "severity": top, "severity_rank": SEVERITY_RANK.get(top, 1), "alert_count": count,
            **{name: sorted(values) for name, values in merged.items()},
        }})

    await db["alerts"].update_one({"_id": alert_id}, {"$set": {"incident_id": incident_id}})
    await update_incident_counters(db, incident_id)
    return incident_id


async def link_alerts(db, alerts: Iterable[dict], noise: Optional[NoiseFilter] = None) -> int:
    """Link a batch oldest-first so incident spans grow in time order."""
    ordered = sorted(alerts, key=lambda a: alert_time(a) or datetime.min)
    linked = 0
    for alert in ordered:
        if await link_alert(db, alert, noise):
            linked += 1
    return linked


async def rebuild_incidents(db, org_id: str, noise: Optional[NoiseFilter] = None) -> dict:
    """Throw away this tenant's incidents and regroup every alert. Safe to run repeatedly."""
    tenant = {"$or": [{"org_id": org_id}, {"org_id": {"$exists": False}}]} if org_id == "default" else {"org_id": org_id}
    await db["incidents"].delete_many(tenant)
    await db["alerts"].update_many(tenant, {"$unset": {"incident_id": ""}})
    alerts = []
    projection = {"org_id": 1, "host": 1, "user": 1, "severity": 1, "rule_name": 1, "extracted_iocs": 1,
                  "first_seen": 1, "created_at": 1, "detected_at": 1, "status": 1, "assignee_id": 1, "assignee_email": 1}
    async for alert in db["alerts"].find(tenant, projection):
        alert.setdefault("org_id", org_id)
        alerts.append(alert)
    linked = await link_alerts(db, alerts, noise)
    async for inc in db["incidents"].find(tenant, {"_id": 1}):
        await update_incident_counters(db, inc["_id"])
    return {"alerts": len(alerts), "linked": linked, "incidents": await db["incidents"].count_documents(tenant)}
