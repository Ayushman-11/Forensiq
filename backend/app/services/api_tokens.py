"""
API tokens for service accounts, with scoped permissions.

A token belongs to one tenant and carries a list of scopes. It is shown once at creation; only a SHA-256 hash is
stored (the token is 240 bits of randomness, so a fast hash is enough). Tokens always expire (default 90 days,
at most 365) and can be revoked at any time.

Authorisation is deny-by-default and has two independent layers:
1. SCOPE_RULES maps (method, path) to the one scope that allows it. A route no rule matches is unreachable with a
   token, so a new endpoint is safe until someone deliberately maps it. tests/test_api_tokens.py pins the full list
   of token-reachable routes and fails when it changes.
2. A token acts as a `soc_analyst`, never a manager or admin, so every manager/admin gate still refuses it even if a
   scope were ever mapped too broadly. Tokens cannot approve or execute response actions, manage tenants, users,
   webhooks or other tokens, or use WebSocket tickets.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

TOKEN_PREFIX = "fsq_"
MAX_ACTIVE_TOKENS = 25
DEFAULT_EXPIRY_DAYS = 90
MAX_EXPIRY_DAYS = 365
SERVICE_ROLE = "soc_analyst"
LAST_USED_RESOLUTION_SECONDS = 60

SCOPES: dict[str, str] = {
    "alerts:read": "Read alerts, statistics, notes, reports and dashboard metrics",
    "alerts:write": "Close, escalate, suppress, assign and annotate alerts; start investigations",
    "incidents:read": "Read incidents, their notes and timelines",
    "incidents:write": "Change incident status and owner, add notes, merge, split, pin, manage ticket links",
    "response:read": "Read response-action requests",
    "response:request": "Request response actions and run dry runs (never approve or execute)",
    "events:read": "Read the outbound event feed",
    "search:execute": "Run SIEM searches",
    "policies:read": "Read SLA and escalation policies",
}

_API = r"^/api/v1"
# (methods, path regex, scope). The first rule that matches decides; no match means no access.
SCOPE_RULES: list[tuple[frozenset, re.Pattern, str]] = [
    (frozenset({"GET"}), re.compile(_API + r"/alerts(/.*)?$"), "alerts:read"),
    (frozenset({"GET"}), re.compile(_API + r"/dashboard/(metrics|soc-metrics|ingestion-health|system-health)$"), "alerts:read"),
    (frozenset({"POST", "PATCH"}), re.compile(_API + r"/alerts/(?!ingest$)(bulk|[^/]+/(disposition|assignee|notes|investigate))$"), "alerts:write"),
    (frozenset({"GET"}), re.compile(_API + r"/incidents(/.*)?$"), "incidents:read"),
    (frozenset({"POST", "DELETE"}), re.compile(_API + r"/incidents/(?!rebuild$)[^/]+/(status|owner|notes|merge|split|pin|tickets)(/.*)?$"), "incidents:write"),
    (frozenset({"GET"}), re.compile(_API + r"/response(/.*)?$"), "response:read"),
    (frozenset({"POST"}), re.compile(_API + r"/response/?$"), "response:request"),
    (frozenset({"POST"}), re.compile(_API + r"/response/[^/]+/dry-run$"), "response:request"),
    (frozenset({"GET"}), re.compile(_API + r"/events/?$"), "events:read"),
    (frozenset({"POST"}), re.compile(_API + r"/search/?$"), "search:execute"),
    (frozenset({"GET"}), re.compile(_API + r"/policies/(sla|escalation)$"), "policies:read"),
]


def required_scope(method: str, path: str) -> Optional[str]:
    for methods, pattern, scope in SCOPE_RULES:
        if method.upper() in methods and pattern.match(path):
            return scope
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


async def create_token(db, user: dict, name: str, scopes: list[str], expires_in_days: Optional[int]) -> tuple[str, dict]:
    name = (name or "").strip()
    if not 2 <= len(name) <= 80:
        raise TokenError(422, "Give the token a name of 2-80 characters")
    scopes = list(dict.fromkeys(scopes))
    unknown = [s for s in scopes if s not in SCOPES]
    if not scopes or unknown:
        raise TokenError(422, f"Choose at least one scope from {sorted(SCOPES)}" + (f"; unknown: {unknown}" if unknown else ""))
    days = DEFAULT_EXPIRY_DAYS if expires_in_days is None else expires_in_days
    if not 1 <= days <= MAX_EXPIRY_DAYS:
        raise TokenError(422, f"Tokens last 1-{MAX_EXPIRY_DAYS} days")
    org = user.get("org_id", "default")
    active = await db["api_tokens"].count_documents({"org_id": org, "revoked_at": None, "expires_at": {"$gt": _now()}})
    if active >= MAX_ACTIVE_TOKENS:
        raise TokenError(409, f"A tenant can have at most {MAX_ACTIVE_TOKENS} active tokens; revoke one first")

    token_id = str(uuid.uuid4())
    token = f"{TOKEN_PREFIX}{token_id.split('-')[0]}_{secrets.token_urlsafe(30)}"
    now = _now()
    doc = {"_id": token_id, "org_id": org, "name": name, "token_hash": hash_token(token), "prefix": token[:12], "scopes": scopes,
           "created_by": user.get("email"), "created_at": now, "expires_at": now + timedelta(days=days), "last_used_at": None, "revoked_at": None}
    await db["api_tokens"].insert_one(doc)
    return token, doc


async def authenticate(db, token: str) -> dict:
    """The service principal for a valid token. Raises TokenError(401) for anything invalid, expired or revoked."""
    doc = await db["api_tokens"].find_one({"token_hash": hash_token(token)}) if token.startswith(TOKEN_PREFIX) else None
    now = _now()
    if not doc or doc.get("revoked_at") or (_aware(doc.get("expires_at")) or now) <= now:
        raise TokenError(401, "Invalid, expired or revoked API token")
    last = _aware(doc.get("last_used_at"))
    if last is None or (now - last).total_seconds() >= LAST_USED_RESOLUTION_SECONDS:
        await db["api_tokens"].update_one({"_id": doc["_id"]}, {"$set": {"last_used_at": now}})
    return {
        "id": f"svc:{doc['_id']}", "email": f"{doc['name']}@service.{doc['org_id']}", "role": SERVICE_ROLE, "org_id": doc["org_id"],
        "is_active": True, "is_service": True, "scopes": list(doc.get("scopes", [])), "token_id": doc["_id"],
    }


def public_token(doc: dict) -> dict:
    def iso(value):
        value = _aware(value)
        return value.isoformat() if value else None

    now = _now()
    revoked, expires = _aware(doc.get("revoked_at")), _aware(doc.get("expires_at"))
    status = "revoked" if revoked else "expired" if expires and expires <= now else "active"
    return {"id": doc["_id"], "name": doc["name"], "prefix": doc["prefix"], "scopes": doc["scopes"], "status": status, "created_by": doc.get("created_by"),
            "created_at": iso(doc.get("created_at")), "expires_at": iso(doc.get("expires_at")), "last_used_at": iso(doc.get("last_used_at")), "revoked_at": iso(revoked)}
