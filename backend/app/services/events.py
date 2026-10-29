"""
Outbound events: a durable outbox with signed webhook delivery and a pull feed.

Every analyst action that is audited becomes an event (the audit trail is the single source of truth), plus
`alert.created` from ingestion. Each event is stored once per tenant with a gap-free sequence number, which backs the
pull feed (`GET /events?after=<seq>`) and fans out to the tenant's webhook subscriptions as `webhook_deliveries`.

Delivery
- POST JSON, 10 s timeout, no redirects, https only. Headers: X-Forensiq-Event, X-Forensiq-Delivery,
  X-Forensiq-Timestamp and X-Forensiq-Signature: sha256=HMAC(secret, "<timestamp>.<body>").
- Receivers should reject timestamps older than a few minutes and compare signatures in constant time.
- Failures retry at 1 min, 5 min, 30 min, 2 h and 6 h, then the delivery is marked dead (and can be redelivered by hand).
  A subscription that keeps failing is disabled so it cannot hold up the queue.
- The target host is resolved at delivery time and refused if it is loopback, link-local, multicast or reserved
  (private ranges are allowed: SOAR platforms usually live there).

Emitting never raises into the caller: an unreachable webhook must not break closing an alert.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pymongo import ReturnDocument

from app.core.logging import logger
from app.services.tenants import decrypt_secret

BACKOFF_SECONDS = (60, 300, 1800, 7200, 21600)
MAX_ATTEMPTS = len(BACKOFF_SECONDS) + 1
DISABLE_AFTER_CONSECUTIVE_FAILURES = 30
CLAIM_TIMEOUT_SECONDS = 120
DELIVERY_TIMEOUT_SECONDS = 10.0
BATCH_SIZE = 50
PATTERN_RE = re.compile(r"^(\*|[a-z_]+\.\*|[a-z_]+\.[a-z_]+)$")
# High-volume or content-heavy audit entries that are not worth an event by default.
EXCLUDED_AUDIT_PREFIXES = ("search.",)
EVENT_FAMILIES = ("alert", "incident", "response", "policy", "tenant", "integration")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def matches(patterns: list[str], event_type: str) -> bool:
    for pattern in patterns:
        if pattern == "*" or pattern == event_type or (pattern.endswith(".*") and event_type.startswith(pattern[:-1])):
            return True
    return False


def validate_patterns(patterns: list[str]) -> list[str]:
    cleaned = list(dict.fromkeys(p.strip().lower() for p in patterns if p and p.strip()))
    if not cleaned or len(cleaned) > 20 or any(not PATTERN_RE.match(p) for p in cleaned):
        raise ValueError("Choose 1-20 event types: '*', a family like 'alert.*', or an exact type like 'alert.close'")
    return cleaned


def sign(secret: str, timestamp: int, body: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), f"{timestamp}.{body}".encode("utf-8"), hashlib.sha256).hexdigest()


# ---------- the outbox ----------

async def _next_seq(db, org_id: str) -> int:
    doc = await db["counters"].find_one_and_update({"_id": f"events:{org_id}"}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    return int(doc["seq"])


async def emit_event(db, org_id: str, event_type: str, data: dict, actor: Optional[str] = None) -> Optional[str]:
    """Record one event and queue it for every matching subscription. Returns the event id, or None if it failed."""
    try:
        event: dict[str, Any] = {"_id": str(uuid.uuid4()), "org_id": org_id, "seq": await _next_seq(db, org_id), "type": event_type,
                 "created_at": _now(), "actor": actor, "data": data}
        await db["outbound_events"].insert_one(event)
        async for sub in db["webhook_subscriptions"].find({"org_id": org_id, "enabled": True}):
            if matches(sub.get("events", []), event_type):
                await db["webhook_deliveries"].insert_one({
                    "_id": str(uuid.uuid4()), "org_id": org_id, "subscription_id": sub["_id"], "event_id": event["_id"], "event_type": event_type,
                    "status": "pending", "attempts": 0, "next_attempt_at": _now(), "created_at": _now(), "last_error": None, "last_status_code": None,
                })
        return str(event["_id"])
    except Exception as exc:
        logger.error("emit_event_failed", event_type=event_type, error=str(exc))
        return None


async def emit_audit_event(db, entry: dict) -> None:
    """Called by record_audit for every audited action."""
    action = entry.get("action", "")
    if action.startswith(EXCLUDED_AUDIT_PREFIXES):
        return
    await emit_event(db, entry.get("org_id", "default"), action, {
        "audit_id": entry.get("_id"), "entity_type": entry.get("entity_type"), "entity_id": entry.get("entity_id"),
        "actor_email": entry.get("actor_email"), "metadata": entry.get("metadata", {}),
    }, actor=entry.get("actor_email"))


async def emit_alerts_created(db, org_id: str, alerts: list[dict]) -> None:
    for alert in alerts:
        await emit_event(db, org_id, "alert.created", {
            "alert_id": alert.get("_id"), "title": alert.get("title"), "severity": alert.get("severity"), "host": alert.get("host"),
            "user": alert.get("user"), "rule_name": alert.get("rule_name"), "status": alert.get("status", "New"),
        })


def public_event(event: dict) -> dict:
    created = _aware(event.get("created_at"))
    return {"id": event["_id"], "seq": event["seq"], "type": event["type"], "tenant": event["org_id"],
            "created_at": created.isoformat() if created else None, "data": event.get("data", {})}


# ---------- delivery ----------

def _client() -> httpx.AsyncClient:
    """Indirection so tests can inject a mock transport."""
    return httpx.AsyncClient(timeout=DELIVERY_TIMEOUT_SECONDS, follow_redirects=False)


async def assert_deliverable(url: str) -> None:
    """Resolve the host now and refuse anything that would reach this server or a metadata endpoint."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("webhook URL must be https")
    host = parsed.hostname
    infos = await asyncio.get_running_loop().getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise ValueError("webhook target resolves to a blocked address")


async def attempt_delivery(db, delivery: dict) -> bool:
    """One attempt. Updates the delivery (and the subscription's health) and returns whether it succeeded."""
    sub = await db["webhook_subscriptions"].find_one({"_id": delivery["subscription_id"], "org_id": delivery["org_id"]})
    event = await db["outbound_events"].find_one({"_id": delivery["event_id"], "org_id": delivery["org_id"]})
    if not sub or not event:
        await db["webhook_deliveries"].update_one({"_id": delivery["_id"]}, {"$set": {"status": "dead", "last_error": "subscription or event no longer exists"}})
        return False

    body = json.dumps(public_event(event), default=str, separators=(",", ":"))
    timestamp = int(time.time())
    secret = decrypt_secret(sub.get("secret_enc"))
    headers = {
        "Content-Type": "application/json", "User-Agent": "Forensiq-Webhooks/1", "X-Forensiq-Event": event["type"],
        "X-Forensiq-Delivery": delivery["_id"], "X-Forensiq-Timestamp": str(timestamp), "X-Forensiq-Signature": sign(secret, timestamp, body),
    }
    status_code: Optional[int] = None
    error: Optional[str] = None
    try:
        await assert_deliverable(sub["url"])
        async with _client() as client:
            resp = await client.post(sub["url"], content=body, headers=headers)
        status_code = resp.status_code
        if not 200 <= status_code < 300:
            error = f"HTTP {status_code}"
    except Exception as exc:  # never store the exception text: it can carry URLs or internals
        error = f"{type(exc).__name__}" if not isinstance(exc, ValueError) else str(exc)[:120]

    attempts = delivery.get("attempts", 0) + 1
    now = _now()
    if error is None:
        await db["webhook_deliveries"].update_one({"_id": delivery["_id"]}, {"$set": {
            "status": "delivered", "attempts": attempts, "delivered_at": now, "last_status_code": status_code, "last_error": None}})
        await db["webhook_subscriptions"].update_one({"_id": sub["_id"]}, {"$set": {"consecutive_failures": 0, "last_success_at": now}})
        return True

    dead = attempts >= MAX_ATTEMPTS
    update: dict[str, Any] = {"status": "dead" if dead else "pending", "attempts": attempts, "last_status_code": status_code, "last_error": error, "last_attempt_at": now}
    if not dead:
        update["next_attempt_at"] = now + timedelta(seconds=BACKOFF_SECONDS[attempts - 1])
    await db["webhook_deliveries"].update_one({"_id": delivery["_id"]}, {"$set": update})
    failures = (sub.get("consecutive_failures") or 0) + 1
    sub_update: dict[str, Any] = {"consecutive_failures": failures, "last_failure_at": now, "last_error": error}
    if failures >= DISABLE_AFTER_CONSECUTIVE_FAILURES and sub.get("enabled"):
        sub_update["enabled"] = False
        sub_update["disabled_reason"] = f"disabled after {failures} consecutive failed deliveries"
        from app.services.audit import record_audit  # late import: audit emits events

        await record_audit(db, {"id": "system", "email": "webhook-dispatcher@forensiq", "org_id": sub["org_id"]}, "integration.webhook_disabled",
                           "webhook", sub["_id"], {"name": sub.get("name"), "failures": failures})
    await db["webhook_subscriptions"].update_one({"_id": sub["_id"]}, {"$set": sub_update})
    return False


async def _claim_due(db, now: datetime) -> list[dict]:
    """Atomically take deliveries that are due, so replicas never send the same one twice."""
    stale = now - timedelta(seconds=CLAIM_TIMEOUT_SECONDS)
    await db["webhook_deliveries"].update_many({"status": "sending", "claimed_at": {"$lt": stale}}, {"$set": {"status": "pending"}})
    claimed = []
    for _ in range(BATCH_SIZE):
        doc = await db["webhook_deliveries"].find_one_and_update(
            {"status": "pending", "next_attempt_at": {"$lte": now}}, {"$set": {"status": "sending", "claimed_at": now}}, sort=[("next_attempt_at", 1)], return_document=ReturnDocument.AFTER)
        if not doc:
            break
        claimed.append(doc)
    return claimed


async def deliver_due(db, now: Optional[datetime] = None) -> int:
    """One dispatcher pass. Returns the number of deliveries attempted."""
    deliveries = await _claim_due(db, now or _now())
    await asyncio.gather(*(attempt_delivery(db, d) for d in deliveries), return_exceptions=True)
    return len(deliveries)


class WebhookDispatcher:
    """Background loop that drains the delivery queue."""

    def __init__(self, db, interval_seconds: int = 5):
        self.db, self.interval = db, interval_seconds
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())
            logger.info("webhook_dispatcher_started", interval=self.interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _loop(self) -> None:
        while self._running:
            try:
                await deliver_due(self.db)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("webhook_dispatch_error", error=str(exc))
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
