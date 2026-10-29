"""
Tenants: registry, per-tenant secrets and the effective configuration every subsystem reads.

Isolation rules this module enforces (and tests/test_tenant_isolation.py proves end to end):
- A tenant other than the platform tenant NEVER falls back to the platform's SIEM. No SIEM settings,
  no polling, no search: otherwise one tenant would read the operator's own telemetry.
- Per-tenant secrets (SIEM password, threat-intel keys) are encrypted at rest and never returned by any API;
  responses only say whether one is set and where the effective value comes from.
- Threat-intel keys may fall back to the platform's (cost only, no tenant data), unless the operator turns that off.
- A tenant with no registry document is a legacy implicit tenant: active, with default behaviour.
  Only an explicit status of "suspended" blocks it.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings
from app.core.logging import logger
from app.normalization.noise import NoiseFilter

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")
RESERVED_IDS = {"system", "admin", "platform", "null", "none", "all", "root", "current", "tenants", "api"}
INDEX_RE = re.compile(r"^[A-Za-z0-9_*-]{1,64}$")
MIN_POLL_SECONDS, MAX_POLL_SECONDS = 10, 3600
_ENC_PREFIX = "enc:v1:"
_BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata", "instance-data"}

STATUSES = ("active", "suspended")
SIEM_TYPES = ("splunk", "elastic")


class TenantError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# ---------- secrets at rest ----------

def _derive(secret: str) -> bytes:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"forensiq/tenant-secrets/v1").derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def _fernet() -> MultiFernet:
    if settings.TENANT_SECRETS_KEY:
        return MultiFernet([Fernet(settings.TENANT_SECRETS_KEY.encode("utf-8"))])
    keys = [Fernet(_derive(settings.SECRET_KEY))]
    if settings.PREVIOUS_SECRET_KEY:  # a rotated SECRET_KEY must not strand stored secrets
        keys.append(Fernet(_derive(settings.PREVIOUS_SECRET_KEY)))
    return MultiFernet(keys)


def encrypt_secret(plain: str) -> str:
    return _ENC_PREFIX + _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(stored: Optional[str]) -> str:
    """The plain secret, or "" when unset or undecryptable (logged; callers treat it as not configured)."""
    if not stored:
        return ""
    if not stored.startswith(_ENC_PREFIX):
        return ""
    try:
        return _fernet().decrypt(stored[len(_ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        logger.error("tenant_secret_undecryptable", hint="SECRET_KEY / TENANT_SECRETS_KEY changed without PREVIOUS_SECRET_KEY")
        return ""


# ---------- validation ----------

def validate_tenant_id(tenant_id: str) -> str:
    tenant_id = (tenant_id or "").strip().lower()
    if tenant_id in RESERVED_IDS or not SLUG_RE.match(tenant_id):
        raise TenantError(422, "Tenant id must be 3-40 characters: lowercase letters, digits and hyphens, not starting or ending with a hyphen, and not a reserved word")
    return tenant_id


def validate_siem_url(url: str) -> str:
    return validate_outbound_url(url, "SIEM")


def validate_outbound_url(url: str, what: str = "URL") -> str:
    """HTTPS only, no credentials in the URL, and never the server itself or a cloud metadata endpoint."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise TenantError(422, f"{what} URL must be an https:// URL")
    if parsed.username or parsed.password:
        raise TenantError(422, "Put credentials in the username and password fields, not in the URL")
    try:
        parsed.port  # raises ValueError for an out-of-range port
    except ValueError:
        raise TenantError(422, f"{what} URL has an invalid port")
    host = parsed.hostname.lower().rstrip(".")
    if host in _BLOCKED_HOSTS or host.endswith(".localhost"):
        raise TenantError(422, f"That {what} host is not allowed")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip and (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved):
        raise TenantError(422, f"That {what} address is not allowed (loopback, link-local, multicast or reserved)")
    return url.rstrip("/")


def validate_index_list(values: list[str]) -> list[str]:
    cleaned = list(dict.fromkeys(v.strip() for v in values if v and v.strip()))
    if len(cleaned) > 50 or any(not INDEX_RE.match(v) for v in cleaned):
        raise TenantError(422, "Indexes must be at most 50 names of letters, digits, '_', '-' or '*'")
    return cleaned


def validate_noise(cfg: dict) -> dict:
    """Same validation the platform policy gets: bad regexes or unknown keys are rejected up front."""
    lists = {"benign_domains": cfg.get("benign_domains") or [], "shared_hosting_domains": cfg.get("shared_hosting_domains") or []}
    for key, values in lists.items():
        if len(values) > 500 or any(not isinstance(v, str) or not v.strip() or len(v) > 253 for v in values):
            raise TenantError(422, f"{key}: at most 500 domain names")
    rules = cfg.get("suppress") or []
    if len(rules) > 200:
        raise TenantError(422, "At most 200 suppression rules")
    try:
        NoiseFilter.from_dict({**lists, "suppress": rules})
    except (ValueError, TypeError, AttributeError) as exc:
        raise TenantError(422, f"Invalid noise policy: {exc}")
    return {**{k: [v.strip() for v in vals] for k, vals in lists.items()}, "suppress": rules}


# ---------- effective configuration ----------

@dataclass
class SiemConfig:
    enabled: bool = False
    configured: bool = False
    type: str = "splunk"  # splunk | elastic
    source: str = "none"  # tenant | platform | none
    url: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    verify_ssl: bool = True
    detection_index: str = ""
    allowed_indexes: list[str] = field(default_factory=list)
    poll_interval_seconds: int = 30


@dataclass
class TenantConfig:
    org_id: str
    name: str = ""
    status: str = "active"
    registered: bool = False
    siem: SiemConfig = field(default_factory=SiemConfig)
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    greynoise_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    ti_sources: dict[str, str] = field(default_factory=dict)  # feed -> tenant | platform | none
    noise: Optional[dict] = None  # tenant policy, or None for the platform policy
    created_at: Optional[datetime] = None

    @property
    def is_platform(self) -> bool:
        return self.org_id == settings.PLATFORM_ORG_ID


def is_platform(org_id: str) -> bool:
    return org_id == settings.PLATFORM_ORG_ID


async def get_tenant_doc(db, org_id: str) -> Optional[dict]:
    return await db["tenants"].find_one({"_id": org_id})


def _platform_siem() -> SiemConfig:
    return SiemConfig(
        enabled=True, configured=bool(settings.SPLUNK_URL and settings.SPLUNK_USERNAME), source="platform", url=settings.SPLUNK_URL,
        username=settings.SPLUNK_USERNAME, password=settings.SPLUNK_PASSWORD, verify_ssl=settings.SPLUNK_VERIFY_SSL,
        detection_index=settings.SPLUNK_DETECTION_INDEX, allowed_indexes=list(settings.SPLUNK_ALLOWED_INDEXES),
        poll_interval_seconds=settings.POLLER_INTERVAL_SECONDS,
    )


async def resolve_config(db, org_id: str) -> TenantConfig:
    doc = await get_tenant_doc(db, org_id) or {}
    stored = doc.get("config") or {}
    cfg = TenantConfig(org_id=org_id, name=doc.get("name") or org_id, status=doc.get("status", "active"),
                       registered=bool(doc), created_at=doc.get("created_at"))

    siem = _platform_siem() if is_platform(org_id) else SiemConfig(detection_index=settings.SPLUNK_DETECTION_INDEX)
    own = stored.get("siem") or {}
    if own:
        siem.source = "tenant"
        for key in ("type", "url", "username", "verify_ssl", "detection_index", "poll_interval_seconds"):
            if own.get(key) not in (None, ""):
                setattr(siem, key, own[key])
        if own.get("allowed_indexes") is not None:
            siem.allowed_indexes = list(own["allowed_indexes"])
        if own.get("password_enc"):
            siem.password = decrypt_secret(own["password_enc"])
        if own.get("api_key_enc"):
            siem.api_key = decrypt_secret(own["api_key_enc"])
        siem.enabled = bool(own.get("enabled", True))
    if siem.type == "elastic":
        siem.configured = bool(siem.url and (siem.api_key or (siem.username and siem.password)))
    else:
        siem.configured = bool(siem.url and siem.username and siem.password)
    if not is_platform(org_id) and not own:
        siem.enabled = False
    cfg.siem = siem

    ti = stored.get("threat_intel") or {}
    for feed, field_name, setting_name in (("virustotal", "vt_api_key", "VT_API_KEY"), ("abuseipdb", "abuseipdb_api_key", "ABUSEIPDB_API_KEY")):
        own_key = decrypt_secret(ti.get(f"{field_name}_enc"))
        platform_key = (getattr(settings, setting_name) or "").strip()
        if own_key:
            value, source = own_key, "tenant"
        elif platform_key and (is_platform(org_id) or settings.TENANT_USE_PLATFORM_THREAT_INTEL):
            value, source = platform_key, "platform"
        else:
            value, source = "", "none"
        setattr(cfg, field_name, value)
        cfg.ti_sources[feed] = source

    for feed, field_name, setting_name in (("otx", "otx_api_key", "OTX_API_KEY"), ("greynoise", "greynoise_api_key", "GREYNOISE_API_KEY")):
        own_key = decrypt_secret(ti.get(f"{field_name}_enc"))
        platform_key = (getattr(settings, setting_name) or "").strip()
        allowed = is_platform(org_id) or settings.TENANT_USE_PLATFORM_THREAT_INTEL
        value, source = (own_key, "tenant") if own_key else ((platform_key, "platform") if platform_key and allowed else ("", "none"))
        setattr(cfg, field_name, value)
        cfg.ti_sources[feed] = source
    # MISP is an organisation's own intelligence: URL and key travel together, from the tenant or (if allowed) the platform.
    own_misp_key = decrypt_secret(ti.get("misp_api_key_enc"))
    if own_misp_key and ti.get("misp_url"):
        cfg.misp_url, cfg.misp_api_key, cfg.ti_sources["misp"] = ti["misp_url"], own_misp_key, "tenant"
    elif settings.MISP_URL and settings.MISP_API_KEY and (is_platform(org_id) or settings.TENANT_USE_PLATFORM_THREAT_INTEL):
        cfg.misp_url, cfg.misp_api_key, cfg.ti_sources["misp"] = settings.MISP_URL, settings.MISP_API_KEY, "platform"
    else:
        cfg.ti_sources["misp"] = "none"

    cfg.noise = stored.get("noise") or None
    return cfg


def noise_filter(cfg: TenantConfig) -> NoiseFilter:
    return NoiseFilter.from_dict(cfg.noise) if cfg.noise else NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH)


def splunk_client(cfg: TenantConfig):
    from app.infrastructure.siem.splunk import SplunkClient

    return SplunkClient(url=cfg.siem.url, username=cfg.siem.username, password=cfg.siem.password, verify_ssl=cfg.siem.verify_ssl)


class UnconfiguredSiem:
    """Stands in for a SIEM the tenant has not set up. Every call fails the way an unreachable SIEM would."""

    async def _fail(self, *_, **__):
        raise RuntimeError("No SIEM is configured for this tenant")

    authenticate = search = list_alerts = list_indexes = _fail

    async def close(self) -> None:
        return None


def elastic_client(cfg: TenantConfig):
    from app.infrastructure.siem.elastic import ElasticClient

    indexes = list(dict.fromkeys([*(cfg.siem.allowed_indexes or []), cfg.siem.detection_index])) if cfg.siem.detection_index else (cfg.siem.allowed_indexes or ["*"])
    return ElasticClient(url=cfg.siem.url, username=cfg.siem.username, password=cfg.siem.password, api_key=cfg.siem.api_key,
                         verify_ssl=cfg.siem.verify_ssl, indexes=indexes)


def siem_client(cfg: TenantConfig):
    """The provider this tenant's SIEM settings select. Callers never need to know which SIEM it is."""
    return elastic_client(cfg) if cfg.siem.type == "elastic" else splunk_client(cfg)


def siem_for(cfg: TenantConfig):
    return siem_client(cfg) if cfg.siem.configured else UnconfiguredSiem()


async def ingestion_kwargs(db, org_id: str) -> dict:
    """Everything IngestionService needs to run as this tenant and no other."""
    cfg = await resolve_config(db, org_id)
    return {
        "splunk_factory": lambda: siem_client(cfg),
        "noise": noise_filter(cfg),
        "detection_index": cfg.siem.detection_index or settings.SPLUNK_DETECTION_INDEX,
    }


async def threat_intel_config(db, org_id: str) -> dict:
    """Every feed credential this tenant may use, keyed by feed. Empty string = not configured."""
    cfg = await resolve_config(db, org_id)
    return {"virustotal": cfg.vt_api_key, "abuseipdb": cfg.abuseipdb_api_key, "otx": cfg.otx_api_key, "greynoise": cfg.greynoise_api_key,
            "misp_url": cfg.misp_url, "misp_key": cfg.misp_api_key}


async def threat_intel_keys(db, org_id: str) -> tuple[str, str]:
    cfg = await resolve_config(db, org_id)
    return cfg.vt_api_key, cfg.abuseipdb_api_key


async def is_suspended(db, org_id: str) -> bool:
    if is_platform(org_id):
        return False
    doc = await db["tenants"].find_one({"_id": org_id}, {"status": 1})
    return bool(doc) and doc.get("status") == "suspended"


# ---------- API views and updates ----------

def public_view(cfg: TenantConfig) -> dict:
    """What the API may show: settings and where they come from, never a secret value."""
    s = cfg.siem
    return {
        "id": cfg.org_id, "name": cfg.name, "status": cfg.status, "registered": cfg.registered, "is_platform": cfg.is_platform,
        "created_at": cfg.created_at.isoformat() if isinstance(cfg.created_at, datetime) else None,
        "siem": {
            "enabled": s.enabled, "configured": s.configured, "type": s.type, "source": s.source, "url": s.url, "username": s.username,
            "password_set": bool(s.password), "api_key_set": bool(s.api_key), "verify_ssl": s.verify_ssl, "detection_index": s.detection_index,
            "allowed_indexes": s.allowed_indexes, "poll_interval_seconds": s.poll_interval_seconds,
        },
        "threat_intel": {
            "virustotal": {"configured": bool(cfg.vt_api_key), "source": cfg.ti_sources.get("virustotal", "none")},
            "abuseipdb": {"configured": bool(cfg.abuseipdb_api_key), "source": cfg.ti_sources.get("abuseipdb", "none")},
            "otx": {"configured": bool(cfg.otx_api_key), "source": cfg.ti_sources.get("otx", "none")},
            "greynoise": {"configured": bool(cfg.greynoise_api_key), "source": cfg.ti_sources.get("greynoise", "none")},
            "misp": {"configured": bool(cfg.misp_api_key), "source": cfg.ti_sources.get("misp", "none"), "url": cfg.misp_url},
        },
        "noise": {"source": "tenant" if cfg.noise else "platform", **(cfg.noise or {})},
    }


async def update_settings(db, org_id: str, update: dict) -> list[str]:
    """
    Apply a validated partial update; returns the names of what changed (never values).
    update = {"siem": {...}|None, "threat_intel": {...}|None, "noise": {...}|None, "reset_noise": bool}
    Secret fields: omitted/None keeps the stored value, "" clears it, anything else replaces it.
    """
    doc = await get_tenant_doc(db, org_id)
    if not doc and is_platform(org_id):
        doc = {"_id": org_id, "name": org_id, "status": "active", "created_at": datetime.now(timezone.utc), "config": {}}
        await db["tenants"].insert_one(doc)
    if not doc:
        raise TenantError(404, "Tenant not found")
    stored = dict(doc.get("config") or {})
    changed: list[str] = []

    if update.get("siem") is not None:
        incoming = update["siem"]
        siem = dict(stored.get("siem") or {})
        if incoming.get("url") is not None:
            siem["url"] = validate_siem_url(incoming["url"]) if incoming["url"] else ""
            changed.append("siem.url")
        if incoming.get("allowed_indexes") is not None:
            siem["allowed_indexes"] = validate_index_list(incoming["allowed_indexes"])
            changed.append("siem.allowed_indexes")
        if incoming.get("detection_index") is not None:
            if incoming["detection_index"] and not INDEX_RE.match(incoming["detection_index"]):
                raise TenantError(422, "Detection index may contain letters, digits, '_', '-' or '*'")
            siem["detection_index"] = incoming["detection_index"]
            changed.append("siem.detection_index")
        if incoming.get("poll_interval_seconds") is not None:
            if not MIN_POLL_SECONDS <= incoming["poll_interval_seconds"] <= MAX_POLL_SECONDS:
                raise TenantError(422, f"Poll interval must be between {MIN_POLL_SECONDS} and {MAX_POLL_SECONDS} seconds")
            siem["poll_interval_seconds"] = incoming["poll_interval_seconds"]
            changed.append("siem.poll_interval_seconds")
        if incoming.get("type") is not None:
            if incoming["type"] not in SIEM_TYPES:
                raise TenantError(422, f"SIEM type must be one of {list(SIEM_TYPES)}")
            siem["type"] = incoming["type"]
            changed.append("siem.type")
        for key in ("enabled", "username", "verify_ssl"):
            if incoming.get(key) is not None:
                siem[key] = incoming[key]
                changed.append(f"siem.{key}")
        if incoming.get("api_key") is not None:
            siem["api_key_enc"] = encrypt_secret(incoming["api_key"]) if incoming["api_key"] else ""
            changed.append("siem.api_key")
        if incoming.get("password") is not None:
            siem["password_enc"] = encrypt_secret(incoming["password"]) if incoming["password"] else ""
            changed.append("siem.password")
        stored["siem"] = siem

    if update.get("threat_intel") is not None:
        ti = dict(stored.get("threat_intel") or {})
        for key in ("vt_api_key", "abuseipdb_api_key", "otx_api_key", "greynoise_api_key", "misp_api_key"):
            value = update["threat_intel"].get(key)
            if value is not None:
                ti[f"{key}_enc"] = encrypt_secret(value) if value else ""
                changed.append(f"threat_intel.{key}")
        if update["threat_intel"].get("misp_url") is not None:
            url = update["threat_intel"]["misp_url"]
            ti["misp_url"] = validate_outbound_url(url, "MISP") if url else ""
            changed.append("threat_intel.misp_url")
        stored["threat_intel"] = ti

    if update.get("reset_noise"):
        stored.pop("noise", None)
        changed.append("noise (reset to platform policy)")
    elif update.get("noise") is not None:
        stored["noise"] = validate_noise(update["noise"])
        changed.append("noise")

    if changed:
        await db["tenants"].update_one({"_id": org_id}, {"$set": {"config": stored, "updated_at": datetime.now(timezone.utc)}})
    return changed
