"""
Alert triage rules: status transitions, verdicts, who may do what, assignment and SLA clocks.

Every state change goes through `apply_disposition` / `assign_alert` so the API, bulk actions
and any future automation enforce the same rules and write the same audit trail.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from app.core.tenancy import scoped_query, tenant_filter
from app.services.audit import record_audit

Action = Literal["close", "escalate", "suppress", "reopen"]
Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "duplicate"]

VERDICTS: dict[str, str] = {
    "true_positive": "True positive",
    "benign_true_positive": "Benign true positive",
    "false_positive": "False positive",
    "duplicate": "Duplicate",
}

OPEN_STATUSES = ("New", "Investigating", "Investigated", "Investigation Failed", "Escalated")
TERMINAL_STATUSES = ("Closed", "Suppressed")
MANAGER_ROLES = ("soc_manager", "admin")
HIGH_SEVERITIES = ("critical", "high")

# Status each action moves to, and the statuses it may start from.
TRANSITIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "close": ("Closed", OPEN_STATUSES),
    "escalate": ("Escalated", ("New", "Investigating", "Investigated", "Investigation Failed")),
    "suppress": ("Suppressed", OPEN_STATUSES),
    "reopen": ("", TERMINAL_STATUSES + ("Escalated",)),
}

# Minutes to first human action (acknowledge) and to resolution, per severity.
SLA_MINUTES: dict[str, tuple[int, int]] = {
    "critical": (15, 4 * 60),
    "high": (60, 24 * 60),
    "medium": (4 * 60, 3 * 24 * 60),
    "low": (24 * 60, 7 * 24 * 60),
}


class TriageError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _aware(ts) -> Optional[datetime]:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return None


def detected_at(alert: dict) -> Optional[datetime]:
    """When Forensiq raised the alert; older alerts only carry the event time."""
    return _aware(alert.get("detected_at")) or _aware(alert.get("created_at"))


def sla_state(alert: dict, now: Optional[datetime] = None) -> Optional[dict]:
    """Acknowledge/resolve deadlines and whether either is breached. None when there is no clock."""
    start = detected_at(alert)
    targets = SLA_MINUTES.get(str(alert.get("severity", "")).lower())
    if not start or not targets:
        return None
    now = now or datetime.now(timezone.utc)
    ack_due = start + timedelta(minutes=targets[0])
    resolve_due = start + timedelta(minutes=targets[1])
    acked = _aware(alert.get("acknowledged_at"))
    resolved = _aware(alert.get("resolved_at"))
    return {
        "ack_due": ack_due.isoformat(),
        "resolve_due": resolve_due.isoformat(),
        "ack_breached": (acked or now) > ack_due,
        "resolve_breached": (resolved or now) > resolve_due,
    }


def _check_permission(user: dict, alert: dict, action: str, verdict: Optional[str]) -> None:
    """L1 analysts cannot make high/critical alerts disappear without a manager."""
    if user.get("role") in MANAGER_ROLES:
        return
    high = str(alert.get("severity", "")).lower() in HIGH_SEVERITIES
    if action == "suppress" and high:
        raise TriageError(403, "Suppressing a high or critical alert requires a SOC manager")
    if action == "close" and high and verdict != "true_positive":
        raise TriageError(403, "Closing a high or critical alert as anything but a true positive requires a SOC manager")
    if action == "reopen" and alert.get("status") == "Suppressed":
        raise TriageError(403, "Reopening a suppressed alert requires a SOC manager")


def _validate(action: str, verdict: Optional[str], note: Optional[str]) -> None:
    if action == "close" and verdict not in VERDICTS:
        raise TriageError(422, f"Closing requires a verdict: one of {sorted(VERDICTS)}")
    if action != "close" and verdict is not None and action != "suppress":
        raise TriageError(422, "Only close and suppress take a verdict")
    if not (note or "").strip():
        raise TriageError(422, f"A note is required to {action} an alert")


async def apply_disposition(
    db, user: dict, alert_id: str, action: str, verdict: Optional[str], note: Optional[str],
) -> dict:
    """Validate and apply one disposition. Raises TriageError; returns the new status fields."""
    if action not in TRANSITIONS:
        raise TriageError(422, f"Unknown action {action!r}")
    _validate(action, verdict, note)
    alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
    if not alert:
        raise TriageError(404, "Alert not found")

    current = alert.get("status", "New")
    target, allowed_from = TRANSITIONS[action]
    if current not in allowed_from:
        raise TriageError(409, f"Cannot {action} an alert that is {current}")
    _check_permission(user, alert, action, verdict)

    now = datetime.now(timezone.utc)
    if action == "reopen":
        target = "Investigated" if alert.get("risk_assessment") else "New"
    update: dict = {"status": target, "updated_at": now, "disposition_note": note.strip()}
    unset: dict = {}
    if action in ("close", "suppress"):
        update.update({"disposition": action, "verdict": verdict, "resolved_at": now, "resolved_by": user.get("email")})
    elif action == "escalate":
        update.update({"disposition": "escalate", "escalated_at": now, "escalated_by": user.get("email")})
    else:  # reopen
        unset = {"disposition": "", "verdict": "", "resolved_at": "", "resolved_by": ""}
    if not alert.get("acknowledged_at"):
        update["acknowledged_at"] = now

    ops: dict = {"$set": update}
    if unset:
        ops["$unset"] = unset
    # Match on the status we validated against so a concurrent change cannot be overwritten.
    result = await db["alerts"].update_one(scoped_query(user, {"_id": alert_id, "status": current}), ops)
    if not result.matched_count:
        raise TriageError(409, "Alert changed while you were working on it; reload and try again")

    await record_audit(db, user, f"alert.{action}", "alert", alert_id, {
        "from": current, "to": target, "verdict": verdict, "note": note.strip(),
    })
    return {"alert_id": alert_id, "status": target, "verdict": update.get("verdict")}


async def assign_alert(db, user: dict, alert_id: str, assignee_id: Optional[str]) -> dict:
    """Assign (or unassign with None). Analysts may only take or release alerts for themselves."""
    is_manager = user.get("role") in MANAGER_ROLES
    alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
    if not alert:
        raise TriageError(404, "Alert not found")

    assignee = None
    if assignee_id is not None:
        if not is_manager and assignee_id != user.get("id"):
            raise TriageError(403, "Analysts can only assign alerts to themselves")
        assignee = await db["users"].find_one({"$and": [tenant_filter(user), {"_id": assignee_id, "is_active": True}]})
        if not assignee:
            raise TriageError(422, "Assignee is not an active user in this organisation")
    elif not is_manager and alert.get("assignee_id") not in (None, user.get("id")):
        raise TriageError(403, "Analysts can only unassign themselves")

    now = datetime.now(timezone.utc)
    update: dict = {"updated_at": now}
    if assignee:
        update.update({"assignee_id": str(assignee["_id"]), "assignee_email": assignee.get("email"), "assigned_at": now})
        if not alert.get("acknowledged_at"):
            update["acknowledged_at"] = now
        ops = {"$set": update}
    else:
        ops = {"$set": update, "$unset": {"assignee_id": "", "assignee_email": "", "assigned_at": ""}}
    await db["alerts"].update_one(scoped_query(user, {"_id": alert_id}), ops)

    await record_audit(db, user, "alert.assigned" if assignee else "alert.unassigned", "alert", alert_id, {
        "from": alert.get("assignee_email"), "to": assignee.get("email") if assignee else None,
    })
    return {"alert_id": alert_id, "assignee_id": update.get("assignee_id"), "assignee_email": update.get("assignee_email")}
