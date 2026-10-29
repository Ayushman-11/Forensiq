"""
Tenant policies for case management: SLA targets and the escalation policy.

Reading is open to any signed-in user (the UI shows the clocks). Changing them is a manager/admin
action, always with a reason, saved as a new immutable version and written to the audit log.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, require_roles
from app.core.tenancy import tenant_id
from app.database.session import get_db
from app.services.policy import get_policy_history, update_policy
from app.services.sla import (
    PolicyValidationError,
    get_escalation_policy,
    get_sla_targets,
    normalise_escalation,
    normalise_sla,
)

router = APIRouter()
manager_required = require_roles("soc_manager", "admin")


class PolicyUpdate(BaseModel):
    content: dict[str, Any]
    reason: str = Field(min_length=3, max_length=500)


def _bad_request(exc: PolicyValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/sla")
async def read_sla(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    targets = await get_sla_targets(db, tenant_id(user))
    return {sev: {"ack_minutes": ack, "resolve_minutes": resolve} for sev, (ack, resolve) in targets.items()}


@router.put("/sla")
async def write_sla(payload: PolicyUpdate, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(manager_required)):
    """Body: {"content": {"critical": [ack_minutes, resolve_minutes], ...}, "reason": "..."}; omitted severities keep defaults."""
    try:
        targets = normalise_sla(payload.content)
    except PolicyValidationError as exc:
        raise _bad_request(exc)
    doc = await update_policy(db, user, "sla_targets", {sev: list(pair) for sev, pair in targets.items()}, payload.reason)
    return {"version": doc["version"], "targets": {sev: {"ack_minutes": a, "resolve_minutes": r} for sev, (a, r) in targets.items()}}


@router.get("/sla/history")
async def sla_history(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(manager_required)):
    return await get_policy_history(db, user, "sla_targets")


@router.get("/escalation")
async def read_escalation(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    return await get_escalation_policy(db, tenant_id(user))


@router.put("/escalation")
async def write_escalation(payload: PolicyUpdate, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(manager_required)):
    """
    Body: {"content": {"critical": {"ack_breach": {"notify": true, "reassign_to": "<user id>", "mark_escalated": false}}}, "reason": "..."}
    `reassign_to` must be an active user of this organisation.
    """
    try:
        policy = normalise_escalation(payload.content)
    except PolicyValidationError as exc:
        raise _bad_request(exc)
    org = tenant_id(user)
    for severity, kinds in policy.items():
        for kind, rule in kinds.items():
            target = rule.get("reassign_to")
            if target is None:
                continue
            owner = await db["users"].find_one({"_id": target, "is_active": True,
                                                "$or": [{"org_id": org}, {"org_id": {"$exists": False}}] if org == "default" else [{"org_id": org}]})
            if not owner:
                raise HTTPException(status_code=422, detail=f"{severity}.{kind}.reassign_to is not an active user in this organisation")
    doc = await update_policy(db, user, "escalation", policy, payload.reason)
    return {"version": doc["version"], "policy": policy}
