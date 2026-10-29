"""
Tenant management and per-tenant settings.

- Admins of the platform tenant (FORENSIQ_PLATFORM_ORG_ID) create, list, rename and suspend tenants, and can
  manage any tenant's settings.
- Admins of any other tenant manage only their own settings, under /tenants/current.

Secrets (SIEM password, threat-intel keys) are write-only: they are encrypted at rest and no response ever
contains one. See services/tenants.py.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, EmailStr, Field

from app.api.deps import require_roles
from app.core.config import settings
from app.core.security import hash_password
from app.core.tenancy import tenant_id
from app.database.session import get_db
from app.services import tenants as svc
from app.services.audit import record_audit

router = APIRouter()
admin_required = require_roles("admin")


async def platform_admin(user: dict = Depends(admin_required)) -> dict:
    if not svc.is_platform(tenant_id(user)):
        raise HTTPException(status_code=403, detail="Only platform administrators can manage tenants")
    return user


def _err(exc: svc.TenantError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


class SiemUpdate(BaseModel):
    type: Optional[str] = Field(default=None, max_length=20, description="splunk or elastic")
    enabled: Optional[bool] = None
    api_key: Optional[str] = Field(default=None, max_length=500, description="Elastic API key (encoded). Omit to keep, empty string to clear")
    url: Optional[str] = Field(default=None, max_length=300)
    username: Optional[str] = Field(default=None, max_length=200)
    password: Optional[str] = Field(default=None, max_length=500, description="Omit to keep, empty string to clear")
    verify_ssl: Optional[bool] = None
    detection_index: Optional[str] = Field(default=None, max_length=64)
    allowed_indexes: Optional[list[str]] = Field(default=None, max_length=50)
    poll_interval_seconds: Optional[int] = None


class ThreatIntelUpdate(BaseModel):
    vt_api_key: Optional[str] = Field(default=None, max_length=300, description="Omit to keep, empty string to clear")
    abuseipdb_api_key: Optional[str] = Field(default=None, max_length=300)
    otx_api_key: Optional[str] = Field(default=None, max_length=300)
    greynoise_api_key: Optional[str] = Field(default=None, max_length=300)
    misp_url: Optional[str] = Field(default=None, max_length=300, description="Your MISP base URL (https)")
    misp_api_key: Optional[str] = Field(default=None, max_length=300)


class NoiseUpdate(BaseModel):
    benign_domains: list[str] = Field(default_factory=list, max_length=500)
    shared_hosting_domains: list[str] = Field(default_factory=list, max_length=500)
    suppress: list[dict] = Field(default_factory=list, max_length=200)


class SettingsUpdate(BaseModel):
    siem: Optional[SiemUpdate] = None
    threat_intel: Optional[ThreatIntelUpdate] = None
    noise: Optional[NoiseUpdate] = None
    reset_noise: bool = False
    reason: str = Field(min_length=3, max_length=500)


class CreateTenant(BaseModel):
    id: str = Field(max_length=40)
    name: str = Field(min_length=2, max_length=120)
    admin_email: EmailStr
    admin_password: str = Field(min_length=12, max_length=128)


class PatchTenant(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    status: Optional[str] = None


async def _audit(db, actor: dict, target_org: str, action: str, metadata: dict) -> None:
    """Written to the target tenant's trail (they can see who changed their settings) and, if different, the actor's."""
    meta = {**metadata, "tenant_id": target_org, "actor_org": tenant_id(actor)}
    await record_audit(db, {**actor, "org_id": target_org}, f"tenant.{action}", "tenant", target_org, meta)
    if tenant_id(actor) != target_org:
        await record_audit(db, actor, f"tenant.{action}", "tenant", target_org, meta)


async def _settings_response(db, org_id: str) -> dict:
    return svc.public_view(await svc.resolve_config(db, org_id))


async def _apply_settings(db, actor: dict, org_id: str, payload: SettingsUpdate) -> dict:
    update = {
        "siem": payload.siem.model_dump(exclude_unset=True) if payload.siem else None,
        "threat_intel": payload.threat_intel.model_dump(exclude_unset=True) if payload.threat_intel else None,
        "noise": payload.noise.model_dump() if payload.noise else None,
        "reset_noise": payload.reset_noise,
    }
    try:
        changed = await svc.update_settings(db, org_id, update)
    except svc.TenantError as exc:
        raise _err(exc)
    await _audit(db, actor, org_id, "settings_updated", {"changed": changed, "reason": payload.reason.strip()})
    return {"changed": changed, "settings": await _settings_response(db, org_id)}


async def _test_siem(db, actor: dict, org_id: str) -> dict:
    cfg = await svc.resolve_config(db, org_id)
    if not cfg.siem.configured:
        raise HTTPException(status_code=409, detail="This tenant has no complete SIEM configuration (URL and credentials)")
    client = svc.siem_client(cfg)
    try:
        await client.authenticate()
        result = {"ok": True, "detail": "Authenticated"}
    except Exception as exc:  # the message names the failure (auth, TLS, unreachable); it contains no secret
        result = {"ok": False, "detail": str(exc)[:300]}
    finally:
        await client.close()
    await _audit(db, actor, org_id, "siem_tested", {"ok": result["ok"]})
    return result


# ---------- your own tenant ----------

@router.get("/current/settings")
async def current_settings(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    return await _settings_response(db, tenant_id(user))


@router.put("/current/settings")
async def update_current_settings(payload: SettingsUpdate, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    return await _apply_settings(db, user, tenant_id(user), payload)


@router.post("/current/settings/siem/test")
async def test_current_siem(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(admin_required)):
    return await _test_siem(db, user, tenant_id(user))


# ---------- platform administration ----------

@router.get("")
async def list_tenants(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    """Registered tenants plus any org id that has users but was never registered (legacy data)."""
    docs = {d["_id"]: d async for d in db["tenants"].find({})}
    for org in await db["users"].distinct("org_id"):
        if org and org not in docs:
            docs[org] = {"_id": org, "name": org, "status": "active", "registered": False}
    rows = []
    for org, doc in sorted(docs.items()):
        users = await db["users"].count_documents({"org_id": org})
        runtime = await db["tenant_runtime"].find_one({"_id": org}) or {}
        rows.append({
            "id": org, "name": doc.get("name", org), "status": doc.get("status", "active"), "registered": doc.get("registered", True),
            "is_platform": svc.is_platform(org), "users": users,
            "siem_configured": (await svc.resolve_config(db, org)).siem.configured,
            "last_poll_at": runtime.get("last_poll_at").isoformat() if isinstance(runtime.get("last_poll_at"), datetime) else None,
            "last_error": runtime.get("last_error"),
        })
    return rows


@router.post("", status_code=201)
async def create_tenant(payload: CreateTenant, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    try:
        org = svc.validate_tenant_id(payload.id)
    except svc.TenantError as exc:
        raise _err(exc)
    if await db["tenants"].find_one({"_id": org}) or await db["users"].find_one({"org_id": org}):
        raise HTTPException(status_code=409, detail="A tenant with that id already exists")
    email = payload.admin_email.strip().lower()
    if await db["users"].find_one({"email": email}):
        raise HTTPException(status_code=409, detail="A user with that email already exists")

    now = datetime.now(timezone.utc)
    await db["tenants"].insert_one({"_id": org, "name": payload.name.strip(), "status": "active", "created_at": now,
                                    "created_by": user.get("email"), "config": {}})
    admin_id = str(uuid.uuid4())
    try:
        await db["users"].insert_one({"_id": admin_id, "email": email, "password_hash": hash_password(payload.admin_password), "role": "admin",
                                      "is_active": True, "mfa_enabled": False, "org_id": org, "created_at": now.isoformat(), "created_by": user["id"]})
    except Exception:
        await db["tenants"].delete_one({"_id": org})
        raise
    await _audit(db, user, org, "created", {"name": payload.name.strip(), "admin_email": email})
    return {"id": org, "name": payload.name.strip(), "status": "active", "admin_user_id": admin_id}


@router.get("/{org_id}")
async def read_tenant(org_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    if not await db["tenants"].find_one({"_id": org_id}) and not await db["users"].find_one({"org_id": org_id}):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return await _settings_response(db, org_id)


@router.patch("/{org_id}")
async def patch_tenant(org_id: str, payload: PatchTenant, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    doc = await db["tenants"].find_one({"_id": org_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Tenant not found (register legacy tenants by updating their settings first)")
    changes: dict = {}
    if payload.name is not None:
        changes["name"] = payload.name.strip()
    if payload.status is not None:
        if payload.status not in svc.STATUSES:
            raise HTTPException(status_code=422, detail=f"Status must be one of {list(svc.STATUSES)}")
        if payload.status == "suspended" and (svc.is_platform(org_id) or org_id == tenant_id(user)):
            raise HTTPException(status_code=409, detail="You cannot suspend your own tenant or the platform tenant")
        changes["status"] = payload.status
    if not changes:
        raise HTTPException(status_code=422, detail="Nothing to change")
    await db["tenants"].update_one({"_id": org_id}, {"$set": {**changes, "updated_at": datetime.now(timezone.utc)}})
    if changes.get("status") == "suspended":  # end live sessions; access tokens die at the next request (see deps)
        ids = [str(u["_id"]) async for u in db["users"].find({"org_id": org_id}, {"_id": 1})]
        await db["sessions"].delete_many({"user_id": {"$in": ids}})
    await _audit(db, user, org_id, "suspended" if changes.get("status") == "suspended" else "updated", changes)
    return {"id": org_id, **{k: v for k, v in changes.items()}}


@router.get("/{org_id}/settings")
async def read_tenant_settings(org_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    if not await db["tenants"].find_one({"_id": org_id}) and not await db["users"].find_one({"org_id": org_id}):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return await _settings_response(db, org_id)


@router.put("/{org_id}/settings")
async def update_tenant_settings(org_id: str, payload: SettingsUpdate, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    if not await db["tenants"].find_one({"_id": org_id}):
        if not await db["users"].find_one({"org_id": org_id}):
            raise HTTPException(status_code=404, detail="Tenant not found")
        # Legacy org with users but no registry entry: register it on first write.
        await db["tenants"].insert_one({"_id": org_id, "name": org_id, "status": "active", "created_at": datetime.now(timezone.utc),
                                        "created_by": user.get("email"), "config": {}})
    return await _apply_settings(db, user, org_id, payload)


@router.post("/{org_id}/settings/siem/test")
async def test_tenant_siem(org_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(platform_admin)):
    if not await db["tenants"].find_one({"_id": org_id}):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return await _test_siem(db, user, org_id)
