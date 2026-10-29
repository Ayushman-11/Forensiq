"""
Response actions: contain a host, disable an account, block an address, behind an approval step.

Lifecycle of a request (every transition is audited, tenant-scoped and, when linked, on the incident timeline):

    pending_approval --approve--> approved --execute--> executing --> succeeded --rollback--> rolled_back
          |  \\--reject--> rejected                         \\--> failed (may be retried while the approval is valid)
          |  \\--cancel--> cancelled
          \\--(time)--> expired        approved --(time)--> expired

Rules that cannot be skipped:
- Four eyes: a SOC manager or admin other than the requester approves. Nobody approves their own request.
- Dry run is always available (read-only against the target) and never needs approval.
- Live execution needs: an approval that has not expired, FORENSIQ_RESPONSE_LIVE_EXECUTION_ENABLED=true,
  a configured connector, a target that is not on the protected list, and the per-hour circuit breaker not tripped.
- Rollback is a manager/admin action, only where the target system can undo it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.config import settings
from app.core.logging import logger
from app.core.tenancy import scoped_query
from app.services import response_connectors as rc
from app.services.audit import record_audit
from app.services.cases import add_event
from app.services.notifications import NotificationEventType, NotificationPayload
from app.services.triage import MANAGER_ROLES

ACTION_TYPES: dict[str, dict[str, Any]] = {
    "edr.isolate_host": {"label": "Isolate host (EDR)", "connector": "crowdstrike", "target": "host", "validate": rc.validate_host,
                         "rollback_label": "Lift isolation"},
    "idp.disable_user": {"label": "Disable user (IdP)", "connector": "okta", "target": "user", "validate": rc.validate_user,
                         "rollback_label": "Re-enable user"},
    "firewall.block_ip": {"label": "Block IP (firewall)", "connector": "firewall", "target": "ip", "validate": rc.validate_ip,
                          "rollback_label": "Unblock IP"},
}

OPEN_STATUSES = ("pending_approval", "approved", "executing")
TERMINAL_STATUSES = ("rejected", "cancelled", "expired", "rolled_back")
MIN_REASON_CHARS = 10


class ResponseError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def _org(user: dict) -> str:
    return str(user.get("org_id") or "default")


def is_manager(user: dict) -> bool:
    return user.get("role") in MANAGER_ROLES


def protected_targets() -> set[str]:
    return {t.strip().lower() for t in settings.RESPONSE_PROTECTED_TARGETS.split(",") if t.strip()}


def capabilities() -> dict:
    return {
        "live_execution_enabled": settings.RESPONSE_LIVE_EXECUTION_ENABLED,
        "approval_ttl_minutes": settings.RESPONSE_APPROVAL_TTL_MINUTES,
        "request_ttl_hours": settings.RESPONSE_REQUEST_TTL_HOURS,
        "max_live_per_hour": settings.RESPONSE_MAX_LIVE_PER_HOUR,
        "actions": {
            key: {"label": spec["label"], "target": spec["target"], "rollback_label": spec["rollback_label"],
                  "rollback": True, "dry_run": True, "connector": spec["connector"], "configured": rc.CONFIGURED[spec["connector"]]()}
            for key, spec in ACTION_TYPES.items()
        },
    }


async def _audit(db, user: dict, request_id: str, action: str, metadata: dict) -> None:
    await record_audit(db, user, f"response.{action}", "response_action", request_id, metadata)


async def _timeline(db, user: dict, doc: dict, event: str, data: dict) -> None:
    if doc.get("incident_id"):
        try:
            await add_event(db, user, doc["incident_id"], event, {"request_id": doc["_id"], "action_type": doc["action_type"], "target": doc["target"], **data})
        except Exception as exc:  # the audit record is the source of truth; a timeline failure must not undo an action
            logger.warning("response_timeline_failed", reason=str(exc))


def _connector_error(exc: rc.ConnectorError) -> ResponseError:
    return ResponseError(exc.status_code, exc.detail)


async def _get(db, user: dict, request_id: str) -> dict:
    doc = await db["response_requests"].find_one(scoped_query(user, {"_id": request_id}))
    if not doc:
        raise ResponseError(404, "Response request not found")
    return await _expire_if_needed(db, doc)


async def _expire_if_needed(db, doc: dict) -> dict:
    now = _now()
    expired_why = None
    if doc["status"] == "pending_approval" and (_aware(doc["requested_at"]) + timedelta(hours=settings.RESPONSE_REQUEST_TTL_HOURS)) < now:
        expired_why = "not approved in time"
    elif doc["status"] == "approved" and _aware(doc["approval"]["expires_at"]) < now:
        expired_why = "approval was not used in time"
    if not expired_why:
        return doc
    result = await db["response_requests"].update_one({"_id": doc["_id"], "status": doc["status"]}, {"$set": {"status": "expired", "expired_reason": expired_why, "updated_at": now}})
    if result.matched_count:
        await record_audit(db, {"id": "system", "email": "system", "org_id": doc.get("org_id", "default")}, "response.expired", "response_action", doc["_id"], {"reason": expired_why})
        doc = {**doc, "status": "expired", "expired_reason": expired_why}
    return doc


def public(doc: dict) -> dict:
    """JSON-safe view: datetimes with an explicit offset, no internal fields."""
    def conv(value):
        if isinstance(value, datetime):
            return _aware(value).isoformat()
        if isinstance(value, dict):
            return {k: conv(v) for k, v in value.items()}
        if isinstance(value, list):
            return [conv(v) for v in value]
        return value

    out = conv(doc)
    out["id"] = out.pop("_id")
    spec = ACTION_TYPES.get(out["action_type"], {})
    out["action_label"] = spec.get("label", out["action_type"])
    out["rollback_label"] = spec.get("rollback_label")
    out["can_rollback"] = out["status"] == "succeeded"
    return out


# ---------- create ----------

async def create_request(db, user: dict, action_type: str, target: str, reason: str,
                         alert_id: Optional[str] = None, incident_id: Optional[str] = None) -> dict:
    spec = ACTION_TYPES.get(action_type)
    if not spec:
        raise ResponseError(422, f"Unknown action {action_type!r}; use one of {sorted(ACTION_TYPES)}")
    reason = (reason or "").strip()
    if len(reason) < MIN_REASON_CHARS:
        raise ResponseError(422, f"Explain why in at least {MIN_REASON_CHARS} characters; approvers read this")
    try:
        target = spec["validate"](target)
    except rc.ConnectorError as exc:
        raise _connector_error(exc)
    if target.lower() in protected_targets():
        raise ResponseError(403, f"{target} is on the protected list and can never be actioned")

    if alert_id and not await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}), {"_id": 1}):
        raise ResponseError(404, "Alert not found")
    if incident_id and not await db["incidents"].find_one(scoped_query(user, {"_id": incident_id}), {"_id": 1}):
        raise ResponseError(404, "Incident not found")

    duplicate = await db["response_requests"].find_one(scoped_query(user, {"action_type": action_type, "target": target, "status": {"$in": list(OPEN_STATUSES)}}))
    if duplicate and (await _expire_if_needed(db, duplicate))["status"] in OPEN_STATUSES:
        raise ResponseError(409, f"There is already an open request for {target} ({duplicate['_id']})")

    preview = await _preview(spec, target)
    now = _now()
    doc = {
        "_id": str(uuid.uuid4()), "org_id": _org(user), "action_type": action_type, "target": target, "reason": reason,
        "alert_id": alert_id, "incident_id": incident_id, "status": "pending_approval",
        "requested_by": {"id": user.get("id"), "email": user.get("email")}, "requested_at": now, "updated_at": now,
        "preview": preview, "executions": [],
    }
    await db["response_requests"].insert_one(doc)
    await _audit(db, user, doc["_id"], "requested", {"action_type": action_type, "target": target, "reason": reason, "alert_id": alert_id, "incident_id": incident_id})
    await _timeline(db, user, doc, "response_requested", {"reason": reason})
    await _notify_approvers(db, doc)
    return doc


async def _preview(spec: dict, target: str) -> dict:
    """Read-only look at the target so approvers see what they are approving. Never blocks the request."""
    connector = rc.CONNECTORS[spec["connector"]]
    if not rc.CONFIGURED[spec["connector"]]():
        return {"status": "not_configured", "summary": f"{spec['connector']} is not configured, so the target could not be checked"}
    try:
        result = await connector.dry_run(target)
        return {"status": "ok", "summary": result.summary, "details": result.details}
    except rc.ConnectorError as exc:
        return {"status": "error", "summary": exc.detail}


async def _notify_approvers(db, doc: dict) -> None:
    try:
        from app.services.sla_monitor import notify_all_channels  # late import: sla_monitor pulls in notifications

        await notify_all_channels(db, NotificationPayload(
            event_type=NotificationEventType.RESPONSE_APPROVAL_REQUESTED, alert_id=doc.get("alert_id") or doc["_id"],
            title=f"Approval needed: {ACTION_TYPES[doc['action_type']]['label']} {doc['target']}",
            severity="high", description=f"{doc['requested_by']['email']} asks: {doc['reason']}",
            details={"request_id": doc["_id"], "action_type": doc["action_type"], "target": doc["target"]},
        ), doc["org_id"])
    except Exception as exc:
        logger.warning("response_notify_failed", reason=str(exc))


# ---------- approve / reject / cancel ----------

async def approve(db, user: dict, request_id: str, note: Optional[str]) -> dict:
    if not is_manager(user):
        raise ResponseError(403, "Only a SOC manager or admin can approve response actions")
    doc = await _get(db, user, request_id)
    if doc["requested_by"].get("id") == user.get("id") or doc["requested_by"].get("email") == user.get("email"):
        raise ResponseError(403, "You cannot approve your own request; ask another manager")
    if doc["status"] != "pending_approval":
        raise ResponseError(409, f"Cannot approve a request that is {doc['status']}")
    now = _now()
    approval: dict[str, Any] = {"by": {"id": user.get("id"), "email": user.get("email")}, "at": now, "note": (note or "").strip() or None,
                "expires_at": now + timedelta(minutes=settings.RESPONSE_APPROVAL_TTL_MINUTES)}
    result = await db["response_requests"].update_one({"_id": request_id, "status": "pending_approval"},
                                                      {"$set": {"status": "approved", "approval": approval, "updated_at": now}})
    if not result.matched_count:
        raise ResponseError(409, "The request changed while you were reviewing it; reload")
    await _audit(db, user, request_id, "approved", {"note": approval["note"], "expires_at": approval["expires_at"].isoformat()})
    await _timeline(db, user, doc, "response_approved", {"by": user.get("email")})
    return await _get(db, user, request_id)


async def reject(db, user: dict, request_id: str, note: str) -> dict:
    if not is_manager(user):
        raise ResponseError(403, "Only a SOC manager or admin can reject response actions")
    note = (note or "").strip()
    if not note:
        raise ResponseError(422, "Say why it is rejected")
    doc = await _get(db, user, request_id)
    if doc["status"] not in ("pending_approval", "approved"):
        raise ResponseError(409, f"Cannot reject a request that is {doc['status']}")
    now = _now()
    result = await db["response_requests"].update_one({"_id": request_id, "status": doc["status"]}, {"$set": {
        "status": "rejected", "rejection": {"by": {"id": user.get("id"), "email": user.get("email")}, "at": now, "note": note}, "updated_at": now}})
    if not result.matched_count:
        raise ResponseError(409, "The request changed while you were reviewing it; reload")
    await _audit(db, user, request_id, "rejected", {"note": note})
    await _timeline(db, user, doc, "response_rejected", {"by": user.get("email"), "note": note})
    return await _get(db, user, request_id)


async def cancel(db, user: dict, request_id: str) -> dict:
    doc = await _get(db, user, request_id)
    if not (is_manager(user) or doc["requested_by"].get("id") == user.get("id")):
        raise ResponseError(403, "Only the requester or a SOC manager can cancel a request")
    if doc["status"] not in ("pending_approval", "approved"):
        raise ResponseError(409, f"Cannot cancel a request that is {doc['status']}")
    result = await db["response_requests"].update_one({"_id": request_id, "status": doc["status"]}, {"$set": {"status": "cancelled", "updated_at": _now()}})
    if not result.matched_count:
        raise ResponseError(409, "The request changed; reload")
    await _audit(db, user, request_id, "cancelled", {})
    await _timeline(db, user, doc, "response_cancelled", {"by": user.get("email")})
    return await _get(db, user, request_id)


# ---------- execute ----------

def _may_run(user: dict, doc: dict) -> bool:
    return is_manager(user) or doc["requested_by"].get("id") == user.get("id")


async def _record_execution(db, request_id: str, entry: dict, extra: Optional[dict] = None) -> None:
    ops: dict = {"$push": {"executions": entry}}
    if extra:
        ops["$set"] = {**extra, "updated_at": _now()}
    await db["response_requests"].update_one({"_id": request_id}, ops)


async def dry_run(db, user: dict, request_id: str) -> dict:
    doc = await _get(db, user, request_id)
    if not _may_run(user, doc):
        raise ResponseError(403, "Only the requester or a SOC manager can run this")
    if doc["status"] in ("rejected", "cancelled", "expired", "rolled_back"):
        raise ResponseError(409, f"Cannot dry-run a request that is {doc['status']}")
    spec = ACTION_TYPES[doc["action_type"]]
    try:
        result = await rc.CONNECTORS[spec["connector"]].dry_run(doc["target"])
        entry = {"at": _now(), "by": user.get("email"), "kind": "dry_run", "ok": True, "summary": result.summary, "details": result.details}
    except rc.ConnectorError as exc:
        entry = {"at": _now(), "by": user.get("email"), "kind": "dry_run", "ok": False, "summary": exc.detail, "details": {}}
    await _record_execution(db, request_id, entry)
    await _audit(db, user, request_id, "dry_run", {"ok": entry["ok"], "summary": entry["summary"]})
    return await _get(db, user, request_id)


async def _guard_live(db, user: dict, doc: dict) -> None:
    if not settings.RESPONSE_LIVE_EXECUTION_ENABLED:
        raise ResponseError(409, "Live execution is switched off on this server (FORENSIQ_RESPONSE_LIVE_EXECUTION_ENABLED). Run a dry run instead")
    spec = ACTION_TYPES[doc["action_type"]]
    if not rc.CONFIGURED[spec["connector"]]():
        raise ResponseError(503, f"{spec['connector']} is not configured on this server")
    if doc["target"].lower() in protected_targets():
        raise ResponseError(403, f"{doc['target']} is on the protected list and can never be actioned")
    since = _now() - timedelta(hours=1)
    recent = await db["response_requests"].count_documents(scoped_query(user, {"executions": {"$elemMatch": {"kind": {"$in": ["execute", "rollback"]}, "at": {"$gte": since}}}}))
    if recent >= settings.RESPONSE_MAX_LIVE_PER_HOUR:
        raise ResponseError(429, f"Circuit breaker: {recent} live actions in the last hour (limit {settings.RESPONSE_MAX_LIVE_PER_HOUR}). Wait, or raise the limit deliberately")


async def execute(db, user: dict, request_id: str) -> dict:
    doc = await _get(db, user, request_id)
    if not _may_run(user, doc):
        raise ResponseError(403, "Only the requester or a SOC manager can run this")
    if doc["status"] not in ("approved", "failed"):
        raise ResponseError(409, f"Cannot execute a request that is {doc['status']}" + (": it needs approval first" if doc["status"] == "pending_approval" else ""))
    if _aware((doc.get("approval") or {}).get("expires_at")) < _now():
        raise ResponseError(409, "The approval has expired; request again")
    await _guard_live(db, user, doc)

    claim = await db["response_requests"].update_one({"_id": request_id, "status": doc["status"]}, {"$set": {"status": "executing", "updated_at": _now()}})
    if not claim.matched_count:
        raise ResponseError(409, "Another execution is already in progress")
    spec = ACTION_TYPES[doc["action_type"]]
    try:
        result = await rc.CONNECTORS[spec["connector"]].execute(doc["target"], reason=doc["reason"], request_id=request_id)
        entry = {"at": _now(), "by": user.get("email"), "kind": "execute", "ok": True, "summary": result.summary, "external_ref": result.external_ref, "details": result.details}
        status = "succeeded"
    except rc.ConnectorError as exc:
        entry = {"at": _now(), "by": user.get("email"), "kind": "execute", "ok": False, "summary": exc.detail, "details": {}}
        status = "failed"
    except Exception as exc:  # never leave a request stuck in "executing"
        logger.error("response_execute_unexpected", request_id=request_id, error=str(exc))
        entry = {"at": _now(), "by": user.get("email"), "kind": "execute", "ok": False, "summary": "Unexpected error while calling the target system", "details": {}}
        status = "failed"
    await _record_execution(db, request_id, entry, {"status": status})
    await _audit(db, user, request_id, "executed" if status == "succeeded" else "execution_failed",
                 {"action_type": doc["action_type"], "target": doc["target"], "summary": entry["summary"], "external_ref": entry.get("external_ref")})
    await _timeline(db, user, doc, "response_executed" if status == "succeeded" else "response_failed", {"summary": entry["summary"]})
    return await _get(db, user, request_id)


async def rollback(db, user: dict, request_id: str, note: str) -> dict:
    if not is_manager(user):
        raise ResponseError(403, "Only a SOC manager or admin can roll back a response action")
    note = (note or "").strip()
    if not note:
        raise ResponseError(422, "Say why it is being rolled back")
    doc = await _get(db, user, request_id)
    if doc["status"] != "succeeded":
        raise ResponseError(409, f"Only a succeeded action can be rolled back (this one is {doc['status']})")
    await _guard_live(db, user, doc)
    claim = await db["response_requests"].update_one({"_id": request_id, "status": "succeeded"}, {"$set": {"status": "executing", "updated_at": _now()}})
    if not claim.matched_count:
        raise ResponseError(409, "Another action is already in progress")
    spec = ACTION_TYPES[doc["action_type"]]
    try:
        result = await rc.CONNECTORS[spec["connector"]].rollback(doc["target"], reason=note, request_id=request_id)
    except rc.ConnectorError as exc:
        # Still in force: put it back to succeeded so it can be retried, and say why it failed.
        await _record_execution(db, request_id, {"at": _now(), "by": user.get("email"), "kind": "rollback", "ok": False, "summary": exc.detail, "details": {}}, {"status": "succeeded"})
        await _audit(db, user, request_id, "rollback_failed", {"summary": exc.detail, "note": note})
        raise _connector_error(exc)
    except Exception as exc:
        logger.error("response_rollback_unexpected", request_id=request_id, error=str(exc))
        await _record_execution(db, request_id, {"at": _now(), "by": user.get("email"), "kind": "rollback", "ok": False, "summary": "Unexpected error while calling the target system", "details": {}}, {"status": "succeeded"})
        raise ResponseError(502, "Unexpected error while calling the target system")
    await _record_execution(db, request_id, {"at": _now(), "by": user.get("email"), "kind": "rollback", "ok": True, "summary": result.summary,
                                             "external_ref": result.external_ref, "details": result.details},
                            {"status": "rolled_back", "rollback": {"by": {"id": user.get("id"), "email": user.get("email")}, "at": _now(), "note": note}})
    await _audit(db, user, request_id, "rolled_back", {"summary": result.summary, "note": note})
    await _timeline(db, user, doc, "response_rolled_back", {"summary": result.summary, "note": note})
    return await _get(db, user, request_id)


async def list_requests(db, user: dict, status: Optional[str] = None, limit: int = 100) -> list[dict]:
    query = scoped_query(user, {"status": status}) if status else scoped_query(user)
    docs = [d async for d in db["response_requests"].find(query).sort("requested_at", -1).limit(limit)]
    return [await _expire_if_needed(db, d) for d in docs]


async def get_request(db, user: dict, request_id: str) -> dict:
    return await _get(db, user, request_id)
