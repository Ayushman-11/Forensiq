"""
Response connectors: the systems that actually change something.

  edr.isolate_host    CrowdStrike Falcon  contain / lift_containment   (host by name or device id)
  idp.disable_user    Okta                suspend + clear sessions / unsuspend
  firewall.block_ip   Webhook gateway     block / unblock              (your automation endpoint)

Each connector offers `dry_run` (a read-only look at the target: what would happen, and would it work),
`execute` and `rollback`. Endpoints and credentials come only from server settings, never from a request.
A connector with no settings raises 503 instead of pretending. The firewall gateway has no read-only
mode, so its dry run says so and sends nothing.

These functions do not decide whether an action is allowed; approval, guardrails and audit live in
services/response_actions.py. Do not call them from anywhere else.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import httpx

from app.core.config import settings

_TIMEOUT = 15.0
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_DEVICE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_USER_RE = re.compile(r"^(?:[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}|00[a-zA-Z0-9]{18})$")


class ConnectorError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class ActionResult:
    summary: str
    ok: bool = True
    external_ref: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


def _client() -> httpx.AsyncClient:
    """Indirection so tests can inject a mock transport."""
    return httpx.AsyncClient(timeout=_TIMEOUT)


async def _send(system: str, method: str, url: str, **kwargs) -> httpx.Response:
    try:
        async with _client() as client:
            resp = await client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise ConnectorError(502, f"{system} is unreachable: {type(exc).__name__}")
    if resp.status_code in (401, 403):
        raise ConnectorError(502, f"{system} rejected the configured credentials or the token lacks permission")
    if resp.status_code == 404:
        raise ConnectorError(404, f"{system} could not find the target")
    if resp.status_code == 429:
        raise ConnectorError(502, f"{system} is rate limiting requests; try again shortly")
    if resp.status_code >= 400:
        raise ConnectorError(502, f"{system} returned HTTP {resp.status_code}")
    return resp


def _json(resp: httpx.Response, system: str) -> Any:
    try:
        return resp.json() if resp.content else {}
    except ValueError:
        raise ConnectorError(502, f"{system} returned an unreadable response")


# ---------- target validation (also used before a request is even created) ----------

def validate_host(target: str) -> str:
    target = (target or "").strip()
    if not (_HOST_RE.match(target) or _DEVICE_ID_RE.match(target.lower())):
        raise ConnectorError(422, "Host must be a hostname or a 32-character device id")
    return target.lower() if _DEVICE_ID_RE.match(target.lower()) else target


def validate_user(target: str) -> str:
    target = (target or "").strip()
    if not _USER_RE.match(target):
        raise ConnectorError(422, "User must be an email/login or an Okta user id")
    return target


def validate_ip(target: str) -> str:
    try:
        ip = ipaddress.ip_address((target or "").strip())
    except ValueError:
        raise ConnectorError(422, "Target must be an IPv4 or IPv6 address")
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise ConnectorError(422, "That address can never be blocked (loopback, link-local, multicast or reserved)")
    return str(ip)


# ---------- CrowdStrike Falcon: host isolation ----------

def crowdstrike_configured() -> bool:
    return bool(settings.CROWDSTRIKE_BASE_URL and settings.CROWDSTRIKE_CLIENT_ID and settings.CROWDSTRIKE_CLIENT_SECRET)


class CrowdStrike:
    system = "crowdstrike"

    @staticmethod
    def _base() -> str:
        if not crowdstrike_configured():
            raise ConnectorError(503, "CrowdStrike is not configured on this server")
        return settings.CROWDSTRIKE_BASE_URL.rstrip("/")

    async def _headers(self) -> dict:
        resp = await _send(self.system, "POST", f"{self._base()}/oauth2/token", data={
            "client_id": settings.CROWDSTRIKE_CLIENT_ID, "client_secret": settings.CROWDSTRIKE_CLIENT_SECRET,
        })
        token = _json(resp, self.system).get("access_token")
        if not token:
            raise ConnectorError(502, "crowdstrike did not return an access token")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    async def _resolve(self, target: str, headers: dict) -> dict:
        """One device or an error. Ambiguous names are refused rather than guessed."""
        base = self._base()
        device_id = target.lower() if _DEVICE_ID_RE.match(target.lower()) else None
        if not device_id:
            resp = await _send(self.system, "GET", f"{base}/devices/queries/devices/v1", headers=headers,
                               params={"filter": f"hostname:'{target}'", "limit": "3"})
            ids = _json(resp, self.system).get("resources") or []
            if not ids:
                raise ConnectorError(404, f"No CrowdStrike device named {target!r}")
            if len(ids) > 1:
                raise ConnectorError(409, f"More than one CrowdStrike device is named {target!r}; use the device id")
            device_id = ids[0]
        resp = await _send(self.system, "GET", f"{base}/devices/entities/devices/v2", headers=headers, params={"ids": device_id})
        rows = _json(resp, self.system).get("resources") or []
        if not rows:
            raise ConnectorError(404, "No CrowdStrike device with that id")
        row = rows[0]
        return {"device_id": row.get("device_id", device_id), "hostname": row.get("hostname"), "status": row.get("status", "unknown"),
                "platform": row.get("platform_name")}

    async def dry_run(self, target: str, rollback: bool = False) -> ActionResult:
        device = await self._resolve(target, await self._headers())
        verb = "lift containment on" if rollback else "network-contain"
        already = device["status"] == ("normal" if rollback else "contained")
        note = f"{device['hostname'] or target} is already {'connected' if rollback else 'contained'}; nothing would change" if already else None
        return ActionResult(f"Would {verb} {device['hostname'] or target}", details={**device, "would_change": not already, "note": note})

    async def _act(self, target: str, action_name: str) -> ActionResult:
        headers = await self._headers()
        device = await self._resolve(target, headers)
        resp = await _send(self.system, "POST", f"{self._base()}/devices/entities/devices-actions/v2", headers=headers,
                           params={"action_name": action_name}, json={"ids": [device["device_id"]]})
        errors = _json(resp, self.system).get("errors") or []
        if errors:
            raise ConnectorError(502, f"crowdstrike refused the action: {errors[0].get('message', 'unknown error')}"[:300])
        verb = "Containment requested for" if action_name == "contain" else "Containment lifted for"
        return ActionResult(f"{verb} {device['hostname'] or target}", external_ref=device["device_id"], details=device)

    async def execute(self, target: str, **_) -> ActionResult:
        return await self._act(target, "contain")

    async def rollback(self, target: str, **_) -> ActionResult:
        return await self._act(target, "lift_containment")


# ---------- Okta: disable user ----------

def okta_configured() -> bool:
    return bool(settings.OKTA_BASE_URL and settings.OKTA_API_TOKEN)


class Okta:
    system = "okta"

    @staticmethod
    def _base() -> str:
        if not okta_configured():
            raise ConnectorError(503, "Okta is not configured on this server")
        return settings.OKTA_BASE_URL.rstrip("/")

    @staticmethod
    def _headers() -> dict:
        return {"Authorization": f"SSWS {settings.OKTA_API_TOKEN}", "Accept": "application/json", "Content-Type": "application/json"}

    async def _user(self, target: str) -> dict:
        resp = await _send(self.system, "GET", f"{self._base()}/api/v1/users/{quote(target, safe='')}", headers=self._headers())
        data = _json(resp, self.system)
        if not data.get("id"):
            raise ConnectorError(404, "Okta could not find that user")
        return {"id": data["id"], "login": (data.get("profile") or {}).get("login", target), "status": data.get("status", "UNKNOWN")}

    async def dry_run(self, target: str, rollback: bool = False) -> ActionResult:
        user = await self._user(target)
        wanted, verb = ("SUSPENDED", "unsuspend") if rollback else ("ACTIVE", "suspend and sign out")
        applicable = user["status"] == wanted
        note = None if applicable else f"{user['login']} is {user['status']}; Okta only allows this from {wanted}"
        return ActionResult(f"Would {verb} {user['login']}", details={**user, "would_change": applicable, "note": note})

    async def execute(self, target: str, **_) -> ActionResult:
        user = await self._user(target)
        if user["status"] != "ACTIVE":
            raise ConnectorError(409, f"{user['login']} is {user['status']}; only an ACTIVE user can be suspended")
        base = self._base()
        await _send(self.system, "POST", f"{base}/api/v1/users/{user['id']}/lifecycle/suspend", headers=self._headers())
        # Suspending blocks new sign-ins; clearing sessions ends the ones already open.
        await _send(self.system, "DELETE", f"{base}/api/v1/users/{user['id']}/sessions", headers=self._headers())
        return ActionResult(f"Suspended {user['login']} and cleared their sessions", external_ref=user["id"], details=user)

    async def rollback(self, target: str, **_) -> ActionResult:
        user = await self._user(target)
        if user["status"] != "SUSPENDED":
            raise ConnectorError(409, f"{user['login']} is {user['status']}; only a SUSPENDED user can be unsuspended")
        await _send(self.system, "POST", f"{self._base()}/api/v1/users/{user['id']}/lifecycle/unsuspend", headers=self._headers())
        return ActionResult(f"Unsuspended {user['login']}", external_ref=user["id"], details=user)


# ---------- Firewall: webhook gateway ----------

def firewall_configured() -> bool:
    return bool(settings.FIREWALL_WEBHOOK_URL)


class FirewallWebhook:
    """
    POSTs {"action": "block"|"unblock", "indicator": ip, "indicator_type": "ipv4"|"ipv6", "reason", "request_id"}
    to FORENSIQ_FIREWALL_WEBHOOK_URL and expects a 2xx. The gateway (a small service in front of PAN-OS,
    FortiGate, a cloud security group, ...) owns the vendor specifics and should be idempotent.
    """

    system = "firewall"

    @staticmethod
    def _base() -> str:
        if not firewall_configured():
            raise ConnectorError(503, "The firewall gateway is not configured on this server")
        return settings.FIREWALL_WEBHOOK_URL

    @staticmethod
    def _headers() -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if settings.FIREWALL_WEBHOOK_TOKEN:
            headers["Authorization"] = f"Bearer {settings.FIREWALL_WEBHOOK_TOKEN}"
        return headers

    async def dry_run(self, target: str, rollback: bool = False) -> ActionResult:
        self._base()
        verb = "unblock" if rollback else "block"
        return ActionResult(f"Would {verb} {target} at the firewall gateway",
                            details={"would_change": True, "note": "The gateway has no read-only mode, so nothing was sent and the current rule state is unknown"})

    async def _post(self, target: str, action: str, reason: str, request_id: str) -> ActionResult:
        ip = ipaddress.ip_address(target)
        resp = await _send(self.system, "POST", self._base(), headers=self._headers(), json={
            "action": action, "indicator": target, "indicator_type": "ipv4" if ip.version == 4 else "ipv6",
            "reason": reason[:500], "request_id": request_id,
        })
        data = _json(resp, self.system)
        ref = data.get("rule_id") or data.get("id") if isinstance(data, dict) else None
        return ActionResult(f"{'Blocked' if action == 'block' else 'Unblocked'} {target} at the firewall gateway",
                            external_ref=str(ref) if ref else None, details={"gateway_response": data if isinstance(data, dict) else {}})

    async def execute(self, target: str, reason: str = "", request_id: str = "", **_) -> ActionResult:
        return await self._post(target, "block", reason, request_id)

    async def rollback(self, target: str, reason: str = "", request_id: str = "", **_) -> ActionResult:
        return await self._post(target, "unblock", reason, request_id)


CONNECTORS: dict[str, Any] = {"crowdstrike": CrowdStrike(), "okta": Okta(), "firewall": FirewallWebhook()}
CONFIGURED: dict[str, Any] = {"crowdstrike": crowdstrike_configured, "okta": okta_configured, "firewall": firewall_configured}
