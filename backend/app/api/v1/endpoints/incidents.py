"""
Incidents: alerts grouped into cases (see services/incidents.py).

An incident has no status of its own. It is open while any member alert is open, so closing,
assigning or escalating alerts (single or bulk) can never leave the incident out of sync.
"""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user, require_roles
from app.core.tenancy import scoped_query, tenant_id
from app.core.timeutil import iso_utc
from app.database.session import get_db
from app.normalization.noise import NoiseFilter
from app.core.config import settings
from app.services.audit import record_audit
from app.services.incidents import SEVERITY_RANK, rebuild_incidents
from app.services.triage import OPEN_STATUSES, sla_state

router = APIRouter()


def _title(incident: dict) -> str:
    rules = incident.get("rules") or []
    hosts = incident.get("hosts") or []
    what = ", ".join(r.replace("_", " ") for r in rules[:2]) or "Related alerts"
    if len(rules) > 2:
        what += f" +{len(rules) - 2} more"
    where = hosts[0] if hosts else "unknown host"
    if len(hosts) > 1:
        where += f" +{len(hosts) - 1} more host{'s' if len(hosts) > 2 else ''}"
    return f"{what} on {where}"


def _summarise(incident: dict, by_status: dict[str, int], assignees: dict) -> dict:
    open_count = sum(n for status, n in by_status.items() if status in OPEN_STATUSES)
    unassigned = assignees.get("unassigned_open", 0)
    owners = assignees.get("owners", set())
    return {
        "id": incident["_id"],
        "title": _title(incident),
        "severity": incident.get("severity", "low"),
        "state": "open" if open_count else "resolved",
        "alert_count": sum(by_status.values()),
        "open_count": open_count,
        "unassigned_open": unassigned,
        "owner": next(iter(owners)) if len(owners) == 1 and not unassigned else None,
        "mixed_owners": len(owners) > 1 or (len(owners) == 1 and unassigned > 0),
        "status_counts": by_status,
        "hosts": incident.get("hosts", []),
        "users": incident.get("users", []),
        "rules": incident.get("rules", []),
        "first_seen": iso_utc(incident["first_seen"]) if isinstance(incident.get("first_seen"), datetime) else None,
        "last_seen": iso_utc(incident["last_seen"]) if isinstance(incident.get("last_seen"), datetime) else None,
    }


async def _member_stats(db, user, incident_ids: list[str]) -> tuple[dict, dict]:
    """Status counts and assignment per incident, from one pass over the member alerts."""
    by_status: dict[str, dict[str, int]] = {i: {} for i in incident_ids}
    assignees: dict[str, dict] = {i: {"owners": set(), "unassigned_open": 0} for i in incident_ids}
    cursor = db["alerts"].find(
        scoped_query(user, {"incident_id": {"$in": incident_ids}}),
        {"incident_id": 1, "status": 1, "assignee_email": 1},
    )
    async for alert in cursor:
        iid = alert["incident_id"]
        status = alert.get("status", "New")
        by_status[iid][status] = by_status[iid].get(status, 0) + 1
        if status in OPEN_STATUSES:
            if alert.get("assignee_email"):
                assignees[iid]["owners"].add(alert["assignee_email"])
            else:
                assignees[iid]["unassigned_open"] += 1
    return by_status, assignees


@router.get("")
async def list_incidents(
    state: Literal["open", "resolved", "all"] = Query("open"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Incidents most recently active first; open ones are ordered by severity."""
    incidents = [i async for i in db["incidents"].find(scoped_query(user)).sort("last_seen", -1).limit(1000)]
    by_status, assignees = await _member_stats(db, user, [i["_id"] for i in incidents])
    rows = [_summarise(i, by_status[i["_id"]], assignees[i["_id"]]) for i in incidents]
    if state != "all":
        rows = [r for r in rows if r["state"] == state]
    # Open first, then severity high to low, then most recently active.
    rows.sort(key=lambda r: r["last_seen"] or "", reverse=True)
    rows.sort(key=lambda r: -SEVERITY_RANK.get(r["severity"], 0))
    rows.sort(key=lambda r: r["state"] != "open")
    return rows[:limit]


@router.get("/{incident_id}")
async def get_incident(incident_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    incident = await db["incidents"].find_one(scoped_query(user, {"_id": incident_id}))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    by_status, assignees = await _member_stats(db, user, [incident_id])
    summary = _summarise(incident, by_status[incident_id], assignees[incident_id])

    members = []
    cursor = db["alerts"].find(
        scoped_query(user, {"incident_id": incident_id}),
        {"title": 1, "severity": 1, "status": 1, "host": 1, "user": 1, "rule_name": 1, "assignee_id": 1, "assignee_email": 1,
         "verdict": 1, "risk_score": 1, "dns_query": 1, "command_line": 1, "detected_at": 1, "created_at": 1,
         "first_seen": 1, "acknowledged_at": 1, "resolved_at": 1},
    ).sort("first_seen", 1)
    async for alert in cursor:
        alert["sla"] = sla_state(alert)
        for key in ("created_at", "detected_at", "first_seen", "acknowledged_at", "resolved_at"):
            if isinstance(alert.get(key), datetime):
                alert[key] = iso_utc(alert[key])
        members.append(alert)
    # Link keys explain why these alerts were grouped; the host/user/domain/hash behind each one.
    summary["link_keys"] = incident.get("keys", [])
    summary["alerts"] = members
    return summary


@router.post("/rebuild")
async def rebuild(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(require_roles("soc_manager", "admin")),
):
    """Regroup every alert in the tenant. Use after changing INCIDENT_WINDOW_HOURS or the noise policy."""
    result = await rebuild_incidents(db, tenant_id(user), NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH))
    await record_audit(db, user, "incidents.rebuilt", "incident", "*", result)
    return result
