"""
Integrations: outbound webhooks, API tokens for service accounts, and the pull event feed.

Management is for human administrators only (API tokens are refused here by default, see services/api_tokens.py).
Secrets are shown once, at creation or rotation, and never again.
"""

import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.api.deps import require_roles
from app.core.tenancy import scoped_query, tenant_id
from app.database.session import get_db
from app.services import api_tokens
from app.services import events as ev
from app.services.audit import record_audit
from app.services.tenants import TenantError, encrypt_secret, validate_outbound_url

router = APIRouter()
feed_router = APIRouter()
admin_required = require_roles("admin")
MAX_WEBHOOKS = 20

EVENT_TYPES = [
    "*", "alert.*", "alert.created", "alert.close", "alert.escalate", "alert.suppress", "alert.reopen", "alert.assigned", "alert.unassigned",
    "alert.note_added", "alert.sla_ack_breach", "alert.sla_resolve_breach", "incident.*", "incident.status_changed", "incident.owner_changed",
    "incident.merged", "incident.split", "incident.note_added", "response.*", "response.requested", "response.approved", "response.executed",
    "response.rolled_back", "policy.updated", "tenant.settings_updated",
]


def _iso(value) -> Optional[str]:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return None


def _public_hook(doc: dict) -> dict:
    return {"id": doc["_id"], "name": doc["name"], "url": doc["url"], "events": doc["events"], "enabled": doc.get("enabled", True),
            "created_by": doc.get("created_by"), "created_at": _iso(doc.get("created_at")), "consecutive_failures": doc.get("consecutive_failures", 0),
            "last_success_at": _iso(doc.get("last_success_at")), "last_failure_at": _iso(doc.get("last_failure_at")), "last_error": doc.get("last_error"),
            "disabled_reason": doc.get("disabled_reason")}


def _public_delivery(doc: dict) -> dict:
    return {"id": doc["_id"], "event_id": doc["event_id"], "event_type": doc["event_type"], "status": doc["status"], "attempts": doc.get("attempts", 0),
            "last_status_code": doc.get("last_status_code"), "last_error": doc.get("last_error"), "created_at": _iso(doc.get("created_at")),
            "next_attempt_at": _iso(doc.get("next_attempt_at")) if doc["status"] == "pending" else None, "delivered_at": _iso(doc.get("delivered_at"))}


def _new_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


class WebhookCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    url: str = Field(max_length=500)
    events: list[str] = Field(default=["*"], max_length=20)


class WebhookPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=80)
    url: Optional[str] = Field(default=None, max_length=500)
    events: Optional[list[str]] = Field(default=None, max_length=20)
    enabled: Optional[bool] = None


class TokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    scopes: list[str] = Field(min_length=1, max_length=20)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=api_tokens.MAX_EXPIRY_DAYS)


def _checked(url: Optional[str], events: Optional[list[str]]):
    try:
        clean_url = validate_outbound_url(url, "Webhook") if url is not None else None
        clean_events = ev.validate_patterns(events) if events is not None else None
    except TenantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return clean_url, clean_events


async def _hook(db, user: dict, webhook_id: str) -> dict:
    doc = await db["webhook_subscriptions"].find_one(scoped_query(user, {"_id": webhook_id}))
    if not doc:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return doc


# ---------- webhooks ----------

@router.get("/event-types")
async def event_types(user: dict = Depends(admin_required)):
    return EVENT_TYPES


@router.get("/webhooks")
async def list_webhooks(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    return [_public_hook(d) async for d in db["webhook_subscriptions"].find(scoped_query(user)).sort("created_at", -1)]


@router.post("/webhooks", status_code=201)
async def create_webhook(payload: WebhookCreate, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    url, events = _checked(payload.url, payload.events)
    if await db["webhook_subscriptions"].count_documents(scoped_query(user)) >= MAX_WEBHOOKS:
        raise HTTPException(status_code=409, detail=f"A tenant can have at most {MAX_WEBHOOKS} webhooks")
    secret = _new_secret()
    doc = {"_id": str(uuid.uuid4()), "org_id": tenant_id(user), "name": payload.name.strip(), "url": url, "events": events, "enabled": True,
           "secret_enc": encrypt_secret(secret), "created_by": user.get("email"), "created_at": datetime.now(timezone.utc), "consecutive_failures": 0}
    await db["webhook_subscriptions"].insert_one(doc)
    await record_audit(db, user, "integration.webhook_created", "webhook", doc["_id"], {"name": doc["name"], "url": url, "events": events})
    return {**_public_hook(doc), "secret": secret, "secret_note": "Store this signing secret now. It is not shown again."}


@router.get("/webhooks/{webhook_id}")
async def read_webhook(webhook_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    return _public_hook(await _hook(db, user, webhook_id))


@router.patch("/webhooks/{webhook_id}")
async def patch_webhook(webhook_id: str, payload: WebhookPatch, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    hook = await _hook(db, user, webhook_id)
    url, events = _checked(payload.url, payload.events)
    changes: dict = {}
    if payload.name is not None:
        changes["name"] = payload.name.strip()
    if url is not None:
        changes["url"] = url
    if events is not None:
        changes["events"] = events
    if payload.enabled is not None:
        changes["enabled"] = payload.enabled
        if payload.enabled:  # re-enabling clears the failure state that disabled it
            changes.update({"consecutive_failures": 0, "disabled_reason": None})
    if not changes:
        raise HTTPException(status_code=422, detail="Nothing to change")
    await db["webhook_subscriptions"].update_one({"_id": hook["_id"]}, {"$set": changes})
    await record_audit(db, user, "integration.webhook_updated", "webhook", webhook_id, {k: v for k, v in changes.items() if k != "disabled_reason"})
    return _public_hook(await _hook(db, user, webhook_id))


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    hook = await _hook(db, user, webhook_id)
    await db["webhook_subscriptions"].delete_one({"_id": hook["_id"]})
    await db["webhook_deliveries"].delete_many({"subscription_id": hook["_id"], "org_id": tenant_id(user)})
    await record_audit(db, user, "integration.webhook_deleted", "webhook", webhook_id, {"name": hook["name"]})
    return {"id": webhook_id, "deleted": True}


@router.post("/webhooks/{webhook_id}/rotate-secret")
async def rotate_secret(webhook_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    hook = await _hook(db, user, webhook_id)
    secret = _new_secret()
    await db["webhook_subscriptions"].update_one({"_id": hook["_id"]}, {"$set": {"secret_enc": encrypt_secret(secret)}})
    await record_audit(db, user, "integration.webhook_secret_rotated", "webhook", webhook_id, {"name": hook["name"]})
    return {"id": webhook_id, "secret": secret, "secret_note": "Store this signing secret now. It is not shown again."}


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    """Send a `webhook.test` event to this endpoint now and report what it answered."""
    hook = await _hook(db, user, webhook_id)
    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await db["outbound_events"].insert_one({"_id": event_id, "org_id": hook["org_id"], "seq": await ev._next_seq(db, hook["org_id"]), "type": "webhook.test",
                                            "created_at": now, "actor": user.get("email"), "data": {"message": "Forensiq webhook test", "webhook_id": webhook_id}})
    delivery = {"_id": str(uuid.uuid4()), "org_id": hook["org_id"], "subscription_id": hook["_id"], "event_id": event_id, "event_type": "webhook.test",
                "status": "sending", "attempts": 0, "next_attempt_at": now, "created_at": now, "last_error": None, "last_status_code": None}
    await db["webhook_deliveries"].insert_one(delivery)
    ok = await ev.attempt_delivery(db, delivery)
    stored = await db["webhook_deliveries"].find_one({"_id": delivery["_id"]})
    if not ok:  # a test is a one-shot: do not leave it in the retry queue
        await db["webhook_deliveries"].update_one({"_id": delivery["_id"]}, {"$set": {"status": "dead"}})
    return {"ok": ok, "status_code": stored.get("last_status_code"), "error": stored.get("last_error")}


@router.get("/webhooks/{webhook_id}/deliveries")
async def list_deliveries(webhook_id: str, limit: int = Query(50, ge=1, le=200), db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    hook = await _hook(db, user, webhook_id)
    cursor = db["webhook_deliveries"].find(scoped_query(user, {"subscription_id": hook["_id"]})).sort("created_at", -1).limit(limit)
    return [_public_delivery(d) async for d in cursor]


@router.post("/webhooks/{webhook_id}/deliveries/{delivery_id}/redeliver")
async def redeliver(webhook_id: str, delivery_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    hook = await _hook(db, user, webhook_id)
    result = await db["webhook_deliveries"].update_one(
        scoped_query(user, {"_id": delivery_id, "subscription_id": hook["_id"], "status": {"$in": ["dead", "delivered"]}}),
        {"$set": {"status": "pending", "attempts": 0, "next_attempt_at": datetime.now(timezone.utc), "last_error": None}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Delivery not found, or still in progress")
    await record_audit(db, user, "integration.webhook_redelivered", "webhook", webhook_id, {"delivery_id": delivery_id})
    return {"id": delivery_id, "status": "pending"}


# ---------- API tokens ----------

@router.get("/scopes")
async def list_scopes(user: dict = Depends(admin_required)):
    return api_tokens.SCOPES


@router.get("/tokens")
async def list_tokens(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    return [api_tokens.public_token(d) async for d in db["api_tokens"].find(scoped_query(user)).sort("created_at", -1)]


@router.post("/tokens", status_code=201)
async def create_token(payload: TokenCreate, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    try:
        token, doc = await api_tokens.create_token(db, user, payload.name, payload.scopes, payload.expires_in_days)
    except api_tokens.TokenError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    await record_audit(db, user, "integration.token_created", "api_token", doc["_id"], {"name": doc["name"], "scopes": doc["scopes"], "expires_at": doc["expires_at"].isoformat()})
    return {**api_tokens.public_token(doc), "token": token, "token_note": "Store this token now. It is not shown again."}


@router.delete("/tokens/{token_id}")
async def revoke_token(token_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    result = await db["api_tokens"].update_one(scoped_query(user, {"_id": token_id, "revoked_at": None}), {"$set": {"revoked_at": datetime.now(timezone.utc)}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Token not found or already revoked")
    await record_audit(db, user, "integration.token_revoked", "api_token", token_id, {})
    return {"id": token_id, "revoked": True}


# ---------- pull feed ----------

@feed_router.get("")
@feed_router.get("/")
async def event_feed(
    after: int = Query(0, ge=0, description="Return events with a sequence number greater than this"),
    limit: int = Query(100, ge=1, le=200),
    type: Optional[str] = Query(None, max_length=60, description="Only this event type, or a family such as alert.*"),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(require_roles("admin", "soc_manager", "soc_analyst")),
):
    """
    Events for your tenant in order. Poll with `after=<next_cursor>` to read everything exactly once.
    Events are kept 30 days.
    """
    query = scoped_query(user, {"seq": {"$gt": after}})
    scanned = [d async for d in db["outbound_events"].find(query).sort("seq", 1).limit(limit if not type else 1000)]
    matched = [d for d in scanned if not type or ev.matches([type], d["type"])]
    if len(matched) >= limit:
        matched = matched[:limit]
        cursor = matched[-1]["seq"]
    else:  # everything scanned is accounted for, so skip past non-matching events too
        cursor = scanned[-1]["seq"] if scanned else after
    return {"events": [ev.public_event(d) for d in matched], "next_cursor": cursor}
