"""
Case management on top of incident grouping (services/incidents.py).

An incident keeps two kinds of state:
- derived: `state` (open/resolved) and the alert counters, computed from member alerts;
- the case itself: `status`, owner, notes, timeline and linked tickets, which analysts set.

Every change goes through this module so the API and any future automation share the rules, write the
same timeline entry and the same audit record. Manual changes (merge, split, pin) mark the incident
`manual`: automatic regrouping may still add new alerts to it, but never absorbs or discards it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from app.core.logging import logger
from app.core.tenancy import scoped_query, tenant_filter
from app.services import ticketing
from app.services.audit import record_audit
from app.services.incidents import SEVERITY_RANK, alert_time, link_keys
from app.services.triage import MANAGER_ROLES, OPEN_STATUSES

CASE_STATUSES = ("open", "in_progress", "resolved", "closed")
CLOSING_STATUSES = ("resolved", "closed")
MAX_NOTE_CHARS = 5000
MAX_MERGE_SOURCES = 10
MAX_TICKETS = 10


class CaseError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _org(user: dict) -> str:
    return str(user.get("org_id") or "default")


async def get_incident_doc(db, user: dict, incident_id: str) -> dict:
    incident = await db["incidents"].find_one(scoped_query(user, {"_id": incident_id}))
    if not incident:
        raise CaseError(404, "Incident not found")
    return incident


async def add_event(db, user: dict, incident_id: str, event_type: str, data: Optional[dict] = None) -> None:
    await db["incident_events"].insert_one({
        "_id": str(uuid.uuid4()), "org_id": _org(user), "incident_id": incident_id, "type": event_type,
        "actor_email": user.get("email", "system"), "at": _now(), "data": data or {},
    })


async def _audit(db, user: dict, incident_id: str, action: str, metadata: dict) -> None:
    await record_audit(db, user, f"incident.{action}", "incident", incident_id, metadata)


async def recompute_incident(db, user: dict, incident_id: str, noise=None) -> Optional[dict]:
    """Rebuild an incident's aggregates from its member alerts; delete it when it has none."""
    members = [a async for a in db["alerts"].find(
        scoped_query(user, {"incident_id": incident_id}),
        {"host": 1, "user": 1, "severity": 1, "rule_name": 1, "extracted_iocs": 1, "first_seen": 1, "created_at": 1, "detected_at": 1},
    )]
    if not members:
        await db["incidents"].delete_one({"_id": incident_id})
        return None
    times = [t for t in (alert_time(a) for a in members) if t]
    keys: set[str] = set()
    for a in members:
        keys.update(link_keys(a, noise))
    fields = {
        "alert_count": len(members),
        "hosts": sorted({a["host"] for a in members if a.get("host") and a["host"] != "Unknown"}),
        "users": sorted({a["user"] for a in members if a.get("user") and a["user"] != "Unknown"}),
        "rules": sorted({a["rule_name"] for a in members if a.get("rule_name")}),
        "severity": max((str(a.get("severity") or "low").lower() for a in members), key=lambda s: SEVERITY_RANK.get(s, 0)),
        "keys": sorted(keys),
        "updated_at": _now(),
    }
    if times:
        fields["first_seen"], fields["last_seen"] = min(times), max(times)
    await db["incidents"].update_one({"_id": incident_id}, {"$set": fields})
    return fields


# ---------- status and owner ----------

async def set_status(db, user: dict, incident_id: str, status: str, note: Optional[str], force: bool = False) -> dict:
    if status not in CASE_STATUSES:
        raise CaseError(422, f"Status must be one of {list(CASE_STATUSES)}")
    incident = await get_incident_doc(db, user, incident_id)
    current = incident.get("status", "open")
    if status == current:
        return {"id": incident_id, "status": status}
    note = (note or "").strip()
    if status in CLOSING_STATUSES and not note:
        raise CaseError(422, f"A note is required to mark an incident {status}")

    if status in CLOSING_STATUSES:
        open_alerts = await db["alerts"].count_documents(scoped_query(user, {"incident_id": incident_id, "status": {"$in": list(OPEN_STATUSES)}}))
        if open_alerts and not (force and user.get("role") in MANAGER_ROLES):
            raise CaseError(409, f"{open_alerts} alert(s) are still open. Close them first"
                                 + (", or a SOC manager can force it" if user.get("role") not in MANAGER_ROLES else ", or pass force"))

    now = _now()
    update: dict = {"status": status, "updated_at": now}
    unset: dict = {}
    if status in CLOSING_STATUSES:
        update.update({"resolved_at": now, "resolved_by": user.get("email"), "resolution_note": note})
    else:
        unset = {"resolved_at": "", "resolved_by": "", "resolution_note": ""}
    ops: dict = {"$set": update}
    if unset:
        ops["$unset"] = unset
    result = await db["incidents"].update_one(scoped_query(user, {"_id": incident_id, "status": {"$in": [current, None]}}) if current != "open"
                                              else scoped_query(user, {"_id": incident_id}), ops)
    if not result.matched_count:
        raise CaseError(409, "Incident changed while you were working on it; reload and try again")

    await add_event(db, user, incident_id, "status_changed", {"from": current, "to": status, "note": note or None, "forced": bool(force and status in CLOSING_STATUSES)})
    await _audit(db, user, incident_id, "status_changed", {"from": current, "to": status, "note": note or None})
    await push_to_tickets(db, user, incident_id, f"Forensiq incident status changed: {current} -> {status}." + (f" Note: {note}" if note else ""))
    return {"id": incident_id, "status": status}


async def set_owner(db, user: dict, incident_id: str, owner_id: Optional[str]) -> dict:
    """Assign (or clear with None). Analysts may only take or release the case for themselves."""
    is_manager = user.get("role") in MANAGER_ROLES
    incident = await get_incident_doc(db, user, incident_id)
    owner = None
    if owner_id is not None:
        if not is_manager and owner_id != user.get("id"):
            raise CaseError(403, "Analysts can only take ownership for themselves")
        owner = await db["users"].find_one({"$and": [tenant_filter(user), {"_id": owner_id, "is_active": True}]})
        if not owner:
            raise CaseError(422, "Owner is not an active user in this organisation")
    elif not is_manager and incident.get("owner_id") not in (None, user.get("id")):
        raise CaseError(403, "Analysts can only release their own cases")

    if owner:
        ops = {"$set": {"owner_id": str(owner["_id"]), "owner_email": owner.get("email"), "owned_at": _now(), "updated_at": _now()}}
    else:
        ops = {"$set": {"updated_at": _now()}, "$unset": {"owner_id": "", "owner_email": "", "owned_at": ""}}
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), ops)
    change = {"from": incident.get("owner_email"), "to": owner.get("email") if owner else None}
    await add_event(db, user, incident_id, "owner_changed", change)
    await _audit(db, user, incident_id, "owner_changed", change)
    return {"id": incident_id, "owner_id": str(owner["_id"]) if owner else None, "owner_email": change["to"]}


# ---------- notes and timeline ----------

async def add_note(db, user: dict, incident_id: str, content: str) -> dict:
    await get_incident_doc(db, user, incident_id)
    content = (content or "").strip()
    if not content:
        raise CaseError(422, "A note cannot be empty")
    if len(content) > MAX_NOTE_CHARS:
        raise CaseError(422, f"Notes are limited to {MAX_NOTE_CHARS} characters")
    note = {"_id": str(uuid.uuid4()), "org_id": _org(user), "incident_id": incident_id, "content": content,
            "author_id": user.get("id"), "author_email": user.get("email"), "created_at": _now()}
    await db["incident_notes"].insert_one(note)
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), {"$set": {"updated_at": note["created_at"]}})
    await add_event(db, user, incident_id, "note_added", {"note_id": note["_id"], "preview": content[:140]})
    await _audit(db, user, incident_id, "note_added", {"note_id": note["_id"]})
    return note


async def list_notes(db, user: dict, incident_id: str, limit: int = 200) -> list[dict]:
    await get_incident_doc(db, user, incident_id)
    cursor = db["incident_notes"].find(scoped_query(user, {"incident_id": incident_id})).sort("created_at", -1).limit(limit)
    return [n async for n in cursor]


async def timeline(db, user: dict, incident_id: str, limit: int = 500) -> list[dict]:
    """Case events plus the detections that make up the incident, oldest first."""
    await get_incident_doc(db, user, incident_id)
    entries: list[dict] = []
    async for e in db["incident_events"].find(scoped_query(user, {"incident_id": incident_id})).sort("at", -1).limit(limit):
        entries.append({"type": e["type"], "at": e["at"], "actor": e.get("actor_email"), "data": e.get("data", {})})
    async for a in db["alerts"].find(scoped_query(user, {"incident_id": incident_id}),
                                     {"title": 1, "severity": 1, "first_seen": 1, "created_at": 1, "detected_at": 1, "resolved_at": 1, "verdict": 1}):
        when = alert_time(a)
        if when:
            entries.append({"type": "alert_detected", "at": when, "actor": None,
                            "data": {"alert_id": str(a["_id"]), "title": a.get("title"), "severity": a.get("severity")}})
        if isinstance(a.get("resolved_at"), datetime):
            entries.append({"type": "alert_resolved", "at": a["resolved_at"], "actor": None,
                            "data": {"alert_id": str(a["_id"]), "title": a.get("title"), "verdict": a.get("verdict")}})

    def _key(entry: dict) -> datetime:
        at = entry["at"]
        return at if at.tzinfo else at.replace(tzinfo=timezone.utc)

    entries.sort(key=_key)
    return entries[-limit:]


# ---------- merge, split, pin ----------

async def merge_incidents(db, user: dict, target_id: str, source_ids: list[str], note: str, noise=None) -> dict:
    sources = list(dict.fromkeys(s for s in source_ids if s != target_id))
    if not sources:
        raise CaseError(422, "Choose at least one other incident to merge in")
    if len(sources) > MAX_MERGE_SOURCES:
        raise CaseError(422, f"Merge at most {MAX_MERGE_SOURCES} incidents at a time")
    if not (note or "").strip():
        raise CaseError(422, "A note explaining the merge is required")
    target = await get_incident_doc(db, user, target_id)
    source_docs = [d async for d in db["incidents"].find(scoped_query(user, {"_id": {"$in": sources}}))]
    if len(source_docs) != len(sources):
        raise CaseError(404, "One or more incidents to merge were not found")

    await db["alerts"].update_many(scoped_query(user, {"incident_id": {"$in": sources}}), {"$set": {"incident_id": target_id}})
    for collection in ("incident_notes", "incident_events"):
        await db[collection].update_many(scoped_query(user, {"incident_id": {"$in": sources}}), {"$set": {"incident_id": target_id}})

    tickets = list(target.get("tickets", []))
    have = {(t["system"], t["key"]) for t in tickets}
    for doc in source_docs:
        for ticket in doc.get("tickets", []):
            if (ticket["system"], ticket["key"]) not in have and len(tickets) < MAX_TICKETS:
                tickets.append(ticket)
                have.add((ticket["system"], ticket["key"]))
    # A merged-in open case must not leave the survivor looking resolved.
    status = target.get("status", "open")
    if status in CLOSING_STATUSES and any(d.get("status", "open") not in CLOSING_STATUSES for d in source_docs):
        status = "open"
    await db["incidents"].update_one(scoped_query(user, {"_id": target_id}), {
        "$set": {"tickets": tickets, "status": status, "manual": True, "updated_at": _now()},
        "$addToSet": {"merged_from": {"$each": sources}},
    })
    await db["incidents"].delete_many(scoped_query(user, {"_id": {"$in": sources}}))
    await recompute_incident(db, user, target_id, noise)

    data = {"sources": sources, "note": note.strip()}
    await add_event(db, user, target_id, "merged", data)
    await _audit(db, user, target_id, "merged", data)
    return {"id": target_id, "merged": sources}


async def split_incident(db, user: dict, incident_id: str, alert_ids: list[str], title: Optional[str], note: str, noise=None) -> dict:
    alert_ids = list(dict.fromkeys(alert_ids))
    if not alert_ids:
        raise CaseError(422, "Choose at least one alert to split off")
    if not (note or "").strip():
        raise CaseError(422, "A note explaining the split is required")
    incident = await get_incident_doc(db, user, incident_id)
    member_ids = {str(a["_id"]) async for a in db["alerts"].find(scoped_query(user, {"incident_id": incident_id}), {"_id": 1})}
    if not set(alert_ids) <= member_ids:
        raise CaseError(422, "Every alert to split off must belong to this incident")
    if len(member_ids - set(alert_ids)) == 0:
        raise CaseError(422, "Splitting off every alert would leave this incident empty; rename or merge it instead")

    new_id = str(uuid.uuid4())
    now = _now()
    doc = {"_id": new_id, "org_id": _org(user), "status": "open", "manual": True, "split_from": incident_id,
           "keys": [], "first_seen": now, "last_seen": now, "severity": "low", "alert_count": 0,
           "created_at": now, "hosts": [], "users": [], "rules": []}
    if title and title.strip():
        doc["title"] = title.strip()[:200]
    await db["incidents"].insert_one(doc)
    # Pinned so a later regroup keeps the analyst's decision instead of re-merging them.
    await db["alerts"].update_many(scoped_query(user, {"_id": {"$in": alert_ids}}), {"$set": {"incident_id": new_id, "incident_pinned": True}})
    await recompute_incident(db, user, new_id, noise)
    await recompute_incident(db, user, incident_id, noise)
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), {"$set": {"manual": True}})

    await add_event(db, user, incident_id, "split", {"new_incident_id": new_id, "alert_ids": alert_ids, "note": note.strip()})
    await add_event(db, user, new_id, "created_by_split", {"from": incident_id, "alert_ids": alert_ids, "note": note.strip()})
    await _audit(db, user, incident_id, "split", {"new_incident_id": new_id, "alert_ids": alert_ids, "note": note.strip()})
    return {"id": incident_id, "new_incident_id": new_id, "moved": alert_ids}


async def pin_alert(db, user: dict, incident_id: str, alert_id: str, noise=None) -> dict:
    """Put one alert in this incident for good: regrouping will not move it back out."""
    await get_incident_doc(db, user, incident_id)
    alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}), {"incident_id": 1, "title": 1})
    if not alert:
        raise CaseError(404, "Alert not found")
    previous = alert.get("incident_id")
    await db["alerts"].update_one(scoped_query(user, {"_id": alert_id}), {"$set": {"incident_id": incident_id, "incident_pinned": True}})
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), {"$set": {"manual": True}})
    await recompute_incident(db, user, incident_id, noise)
    if previous and previous != incident_id:
        await recompute_incident(db, user, previous, noise)
        await add_event(db, user, previous, "alert_moved_out", {"alert_id": alert_id, "to": incident_id})
    await add_event(db, user, incident_id, "alert_pinned", {"alert_id": alert_id, "title": alert.get("title"), "from": previous})
    await _audit(db, user, incident_id, "alert_pinned", {"alert_id": alert_id, "from": previous})
    return {"id": incident_id, "alert_id": alert_id, "pinned": True, "previous_incident_id": previous}


async def unpin_alert(db, user: dict, incident_id: str, alert_id: str) -> dict:
    """Release the pin; the alert stays where it is until the next regroup decides otherwise."""
    await get_incident_doc(db, user, incident_id)
    result = await db["alerts"].update_one(scoped_query(user, {"_id": alert_id, "incident_id": incident_id, "incident_pinned": True}),
                                           {"$unset": {"incident_pinned": ""}})
    if not result.matched_count:
        raise CaseError(404, "That alert is not pinned to this incident")
    await add_event(db, user, incident_id, "alert_unpinned", {"alert_id": alert_id})
    await _audit(db, user, incident_id, "alert_unpinned", {"alert_id": alert_id})
    return {"id": incident_id, "alert_id": alert_id, "pinned": False}


# ---------- external tickets ----------

def _incident_brief(incident: dict) -> str:
    return (f"Forensiq incident {incident['_id']}: severity {incident.get('severity', 'unknown')}, "
            f"{incident.get('alert_count', 0)} alert(s), hosts: {', '.join(incident.get('hosts', [])[:5]) or 'n/a'}, "
            f"users: {', '.join(incident.get('users', [])[:5]) or 'n/a'}, rules: {', '.join(incident.get('rules', [])[:5]) or 'n/a'}.")


async def link_ticket(db, user: dict, incident_id: str, system: str, key: Optional[str], create: bool, title: str) -> dict:
    incident = await get_incident_doc(db, user, incident_id)
    tickets = incident.get("tickets", [])
    if len(tickets) >= MAX_TICKETS:
        raise CaseError(409, f"An incident can link at most {MAX_TICKETS} tickets")
    try:
        if create:
            info = await ticketing.create_ticket(system, title, _incident_brief(incident))
        else:
            key = ticketing.validate_key(system, key or "")
            if ticketing.is_configured(system):
                info = await ticketing.fetch_ticket(system, key)
            else:  # linkable by hand; nothing to sync until the connector is configured
                info = ticketing.TicketInfo(key=key, url=ticketing.ticket_url(system, key) or "", external_status="unknown", status=None)
    except ticketing.TicketError as exc:
        raise CaseError(exc.status_code, exc.detail)
    if any(t["system"] == system and t["key"] == info.key for t in tickets):
        raise CaseError(409, f"{info.key} is already linked to this incident")

    ticket = {"id": str(uuid.uuid4()), "system": system, "key": info.key, "url": info.url, "external_status": info.external_status,
              "mapped_status": info.status, "applied_status": info.status, "sys_id": info.sys_id, "linked_by": user.get("email"), "linked_at": _now(),
              "last_synced_at": _now() if ticketing.is_configured(system) else None,
              "sync_state": "ok" if ticketing.is_configured(system) else "not_configured", "sync_error": None, "created_by_forensiq": bool(create)}
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), {"$push": {"tickets": ticket}, "$set": {"updated_at": _now()}})
    await add_event(db, user, incident_id, "ticket_created" if create else "ticket_linked", {"system": system, "key": info.key})
    await _audit(db, user, incident_id, "ticket_linked", {"system": system, "key": info.key, "created": create})
    return ticket


async def unlink_ticket(db, user: dict, incident_id: str, ticket_id: str) -> dict:
    incident = await get_incident_doc(db, user, incident_id)
    ticket = next((t for t in incident.get("tickets", []) if t["id"] == ticket_id), None)
    if not ticket:
        raise CaseError(404, "Ticket link not found")
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), {"$pull": {"tickets": {"id": ticket_id}}})
    await add_event(db, user, incident_id, "ticket_unlinked", {"system": ticket["system"], "key": ticket["key"]})
    await _audit(db, user, incident_id, "ticket_unlinked", {"system": ticket["system"], "key": ticket["key"]})
    return {"id": incident_id, "unlinked": ticket["key"]}


async def sync_ticket(db, user: dict, incident_id: str, ticket_id: str, apply: bool = True) -> dict:
    """Pull the ticket's status. With `apply`, the incident follows it (external systems own their workflow)."""
    incident = await get_incident_doc(db, user, incident_id)
    ticket = next((t for t in incident.get("tickets", []) if t["id"] == ticket_id), None)
    if not ticket:
        raise CaseError(404, "Ticket link not found")
    if not ticketing.is_configured(ticket["system"]):
        raise CaseError(503, f"{ticket['system']} is not configured on this server, so there is nothing to sync")
    set_fields: dict = {}
    try:
        info = await ticketing.fetch_ticket(ticket["system"], ticket["key"])
    except ticketing.TicketError as exc:
        set_fields = {"tickets.$.sync_state": "error", "tickets.$.sync_error": exc.detail}
        await db["incidents"].update_one(scoped_query(user, {"_id": incident_id, "tickets.id": ticket_id}), {"$set": set_fields})
        raise CaseError(exc.status_code, exc.detail)

    set_fields = {"tickets.$.external_status": info.external_status, "tickets.$.mapped_status": info.status,
                  "tickets.$.sys_id": info.sys_id or ticket.get("sys_id"), "tickets.$.last_synced_at": _now(),
                  "tickets.$.sync_state": "ok", "tickets.$.sync_error": None}
    await db["incidents"].update_one(scoped_query(user, {"_id": incident_id, "tickets.id": ticket_id}), {"$set": set_fields})

    changed = bool(ticket.get("external_status") and ticket.get("external_status") != info.external_status)
    if changed:
        await add_event(db, user, incident_id, "ticket_synced", {"key": ticket["key"], "from": ticket.get("external_status"), "to": info.external_status})
    applied = None
    current = incident.get("status", "open")
    # `applied_status` is the last external status the incident followed, so a sync that was told not to apply
    # can be applied later, and an analyst who reopens the case is not overridden by the same ticket state.
    if apply and info.status and info.status != current and info.status != ticket.get("applied_status"):
        # The external system decided; skip the open-alert guard and say so in the note.
        now = _now()
        update = {"status": info.status, "updated_at": now}
        if info.status in CLOSING_STATUSES:
            update.update({"resolved_at": now, "resolved_by": f"{ticket['system']}:{ticket['key']}",
                           "resolution_note": f"Status followed {ticket['system']} ticket {ticket['key']} ({info.external_status})"})
        await db["incidents"].update_one(scoped_query(user, {"_id": incident_id}), {"$set": update})
        await add_event(db, user, incident_id, "status_changed", {"from": current, "to": info.status, "source": f"{ticket['system']}:{ticket['key']}"})
        await db["incidents"].update_one(scoped_query(user, {"_id": incident_id, "tickets.id": ticket_id}), {"$set": {"tickets.$.applied_status": info.status}})
        await _audit(db, user, incident_id, "status_synced", {"from": current, "to": info.status, "ticket": ticket["key"]})
        applied = info.status
    return {"id": incident_id, "ticket_id": ticket_id, "external_status": info.external_status, "mapped_status": info.status, "applied_status": applied}


async def push_to_tickets(db, user: dict, incident_id: str, text: str) -> None:
    """Best-effort: tell linked tickets what changed. Never fails the case action that triggered it."""
    incident = await db["incidents"].find_one(scoped_query(user, {"_id": incident_id}), {"tickets": 1})
    for ticket in (incident or {}).get("tickets", []):
        if not ticketing.is_configured(ticket["system"]):
            continue
        try:
            await ticketing.push_comment(ticket["system"], ticket["key"], text, ticket.get("sys_id"))
        except ticketing.TicketError as exc:
            logger.warning("ticket_comment_failed", system=ticket["system"], key=ticket["key"], reason=exc.detail)
            await db["incidents"].update_one(scoped_query(user, {"_id": incident_id, "tickets.id": ticket["id"]}),
                                             {"$set": {"tickets.$.sync_state": "error", "tickets.$.sync_error": exc.detail}})


async def sync_all_tickets(db) -> int:
    """Background pass over every tenant's open incidents with linked tickets. Returns tickets checked."""
    system_user = {"id": "system", "email": "ticket-sync@forensiq", "role": "admin"}
    checked = 0
    async for incident in db["incidents"].find({"tickets.0": {"$exists": True}, "status": {"$nin": list(CLOSING_STATUSES)}}):
        actor = {**system_user, "org_id": incident.get("org_id", "default")}
        for ticket in incident.get("tickets", []):
            if not ticketing.is_configured(ticket["system"]):
                continue
            try:
                await sync_ticket(db, actor, incident["_id"], ticket["id"], apply=True)
            except CaseError as exc:
                logger.warning("ticket_sync_failed", incident_id=incident["_id"], key=ticket["key"], reason=exc.detail)
            checked += 1
    return checked
