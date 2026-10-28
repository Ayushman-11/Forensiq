"""
Incidents: alerts grouped into cases (see services/incidents.py).

`state` (open/resolved) is derived: an incident is open while any member alert is open, so closing,
assigning or escalating alerts (single or bulk) can never leave it out of sync.

The case itself (services/cases.py) has its own `status`, owner, notes, timeline and external tickets,
and analysts can merge, split and pin alerts manually.
"""

from datetime import datetime
from typing import Literal

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user, require_roles
from app.core.tenancy import scoped_query, tenant_id
from app.core.timeutil import iso_utc
from app.database.session import get_db
from app.normalization.noise import NoiseFilter
from app.core.config import settings
from app.services.audit import record_audit
from app.services import cases
from app.services.incidents import SEVERITY_RANK, rebuild_incidents
from app.services.sla import get_sla_targets
from app.services.tenants import noise_filter, resolve_config
from app.services.triage import OPEN_STATUSES, sla_state

router = APIRouter()


async def _noise(db, user: dict) -> Optional[NoiseFilter]:
    try:
        return noise_filter(await resolve_config(db, tenant_id(user)))
    except Exception:  # regrouping falls back to un-filtered keys rather than failing the action
        return None


def _case_error(exc: cases.CaseError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def _public_ticket(ticket: dict) -> dict:
    out = {k: v for k, v in ticket.items() if k != "sys_id"}
    for key in ("linked_at", "last_synced_at"):
        if isinstance(out.get(key), datetime):
            out[key] = iso_utc(out[key])
    return out


def _title(incident: dict) -> str:
    if incident.get("title"):
        return incident["title"]
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
        "status": incident.get("status", "open"),
        "case_owner": incident.get("owner_email"),
        "case_owner_id": incident.get("owner_id"),
        "manual": bool(incident.get("manual")),
        "tickets": [_public_ticket(t) for t in incident.get("tickets", [])],
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
         "first_seen": 1, "acknowledged_at": 1, "resolved_at": 1, "incident_pinned": 1},
    ).sort("first_seen", 1)
    sla_targets = await get_sla_targets(db, tenant_id(user))
    async for alert in cursor:
        alert["sla"] = sla_state(alert, targets_by_severity=sla_targets)
        for key in ("created_at", "detected_at", "first_seen", "acknowledged_at", "resolved_at"):
            if isinstance(alert.get(key), datetime):
                alert[key] = iso_utc(alert[key])
        members.append(alert)
    # Link keys explain why these alerts were grouped; the host/user/domain/hash behind each one.
    summary["link_keys"] = incident.get("keys", [])
    summary["resolution_note"] = incident.get("resolution_note")
    summary["merged_from"] = incident.get("merged_from", [])
    summary["split_from"] = incident.get("split_from")
    summary["pinned_alert_ids"] = [str(a["_id"]) for a in members if a.get("incident_pinned")]
    summary["alerts"] = members
    return summary


@router.post("/rebuild")
async def rebuild(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(require_roles("soc_manager", "admin")),
):
    """Regroup every alert in the tenant. Use after changing INCIDENT_WINDOW_HOURS or the noise policy."""
    result = await rebuild_incidents(db, tenant_id(user), await _noise(db, user))
    await record_audit(db, user, "incidents.rebuilt", "incident", "*", result)
    return result


# ---------- case management ----------

class StatusRequest(BaseModel):
    status: str
    note: Optional[str] = Field(default=None, max_length=cases.MAX_NOTE_CHARS)
    force: bool = False


class OwnerRequest(BaseModel):
    owner_id: Optional[str] = None


class NoteRequest(BaseModel):
    content: str = Field(max_length=cases.MAX_NOTE_CHARS)


class MergeRequest(BaseModel):
    source_ids: list[str] = Field(min_length=1, max_length=cases.MAX_MERGE_SOURCES)
    note: str = Field(max_length=cases.MAX_NOTE_CHARS)


class SplitRequest(BaseModel):
    alert_ids: list[str] = Field(min_length=1, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    note: str = Field(max_length=cases.MAX_NOTE_CHARS)


class PinRequest(BaseModel):
    alert_id: str


class TicketRequest(BaseModel):
    system: Literal["jira", "servicenow"]
    key: Optional[str] = Field(default=None, max_length=40)
    create: bool = False


def _serialise(doc: dict, *datetime_keys: str) -> dict:
    out = dict(doc)
    for key in datetime_keys:
        if isinstance(out.get(key), datetime):
            out[key] = iso_utc(out[key])
    return out


@router.post("/{incident_id}/status")
async def change_status(incident_id: str, payload: StatusRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return await cases.set_status(db, user, incident_id, payload.status, payload.note, payload.force)
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/owner")
async def change_owner(incident_id: str, payload: OwnerRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return await cases.set_owner(db, user, incident_id, payload.owner_id)
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/notes", status_code=201)
async def add_incident_note(incident_id: str, payload: NoteRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return _serialise(await cases.add_note(db, user, incident_id, payload.content), "created_at")
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.get("/{incident_id}/notes")
async def list_incident_notes(incident_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return [_serialise(n, "created_at") for n in await cases.list_notes(db, user, incident_id)]
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.get("/{incident_id}/timeline")
async def incident_timeline(incident_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return [_serialise(e, "at") for e in await cases.timeline(db, user, incident_id)]
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/merge")
async def merge(incident_id: str, payload: MergeRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Fold other incidents into this one. Their alerts, notes, timeline and tickets move here."""
    try:
        return await cases.merge_incidents(db, user, incident_id, payload.source_ids, payload.note, await _noise(db, user))
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/split")
async def split(incident_id: str, payload: SplitRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Move some of this incident's alerts into a new incident."""
    try:
        return await cases.split_incident(db, user, incident_id, payload.alert_ids, payload.title, payload.note, await _noise(db, user))
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/pin")
async def pin(incident_id: str, payload: PinRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Pin an alert to this incident (moving it from wherever it was); regrouping will not undo it."""
    try:
        return await cases.pin_alert(db, user, incident_id, payload.alert_id, await _noise(db, user))
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.delete("/{incident_id}/pin/{alert_id}")
async def unpin(incident_id: str, alert_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return await cases.unpin_alert(db, user, incident_id, alert_id)
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/tickets", status_code=201)
async def link_ticket(incident_id: str, payload: TicketRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Link an existing ticket by key, or create one in Jira / ServiceNow (`create: true`)."""
    try:
        incident = await cases.get_incident_doc(db, user, incident_id)
        ticket = await cases.link_ticket(db, user, incident_id, payload.system, payload.key, payload.create, _title(incident))
        return _public_ticket(ticket)
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.post("/{incident_id}/tickets/{ticket_id}/sync")
async def sync_ticket(incident_id: str, ticket_id: str, apply: bool = Query(True), db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Pull the ticket's current status; with apply=true the incident's status follows it."""
    try:
        return await cases.sync_ticket(db, user, incident_id, ticket_id, apply)
    except cases.CaseError as exc:
        raise _case_error(exc)


@router.delete("/{incident_id}/tickets/{ticket_id}")
async def unlink_ticket(incident_id: str, ticket_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return await cases.unlink_ticket(db, user, incident_id, ticket_id)
    except cases.CaseError as exc:
        raise _case_error(exc)
