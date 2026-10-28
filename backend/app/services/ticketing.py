"""
External ticket connectors (Jira, ServiceNow) for case management.

Operations: look up a ticket's status, create a ticket for an incident, and add a comment.
Base URLs and credentials come only from server configuration, never from a request, so a user
cannot point the server at an arbitrary host. A system with no configuration reports
`not_configured` instead of pretending to work; callers may still record a link by hand.

External statuses map onto the incident's case statuses (open / in_progress / resolved / closed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

import httpx

from app.core.config import settings

SYSTEMS = ("jira", "servicenow")

_JIRA_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,19}-\d{1,9}$")
_SERVICENOW_KEY_RE = re.compile(r"^[A-Z]{3,10}\d{4,12}$")
_TIMEOUT = 10.0

_JIRA_CATEGORY = {"new": "open", "indeterminate": "in_progress", "done": "resolved"}
_SERVICENOW_STATE = {"1": "open", "2": "in_progress", "3": "in_progress", "4": "in_progress", "5": "in_progress",
                     "6": "resolved", "7": "closed", "8": "closed"}


class TicketError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class TicketInfo:
    key: str
    url: str
    external_status: str
    status: Optional[str]  # mapped case status, None when the external state is not recognised
    summary: str = ""
    sys_id: Optional[str] = None


def _client() -> httpx.AsyncClient:
    """Indirection so tests can inject a mock transport."""
    return httpx.AsyncClient(timeout=_TIMEOUT)


def is_configured(system: str) -> bool:
    if system == "jira":
        return bool(settings.JIRA_BASE_URL and settings.JIRA_EMAIL and settings.JIRA_API_TOKEN)
    if system == "servicenow":
        return bool(settings.SERVICENOW_INSTANCE_URL and settings.SERVICENOW_USER and settings.SERVICENOW_PASSWORD)
    return False


def validate_key(system: str, key: str) -> str:
    if system not in SYSTEMS:
        raise TicketError(422, f"Unknown ticket system {system!r}; use one of {list(SYSTEMS)}")
    key = (key or "").strip().upper()
    pattern = _JIRA_KEY_RE if system == "jira" else _SERVICENOW_KEY_RE
    if not pattern.match(key):
        example = "SEC-123" if system == "jira" else "INC0012345"
        raise TicketError(422, f"{key or 'Ticket key'!r} is not a valid {system} key (for example {example})")
    return key


def ticket_url(system: str, key: str) -> Optional[str]:
    if system == "jira" and settings.JIRA_BASE_URL:
        return f"{settings.JIRA_BASE_URL.rstrip('/')}/browse/{quote(key)}"
    if system == "servicenow" and settings.SERVICENOW_INSTANCE_URL:
        return f"{settings.SERVICENOW_INSTANCE_URL.rstrip('/')}/incident.do?sysparm_query=number={quote(key)}"
    return None


def _require(system: str) -> None:
    if not is_configured(system):
        raise TicketError(503, f"{system} is not configured on this server")


def _auth(system: str) -> httpx.BasicAuth:
    if system == "jira":
        return httpx.BasicAuth(settings.JIRA_EMAIL, settings.JIRA_API_TOKEN)
    return httpx.BasicAuth(settings.SERVICENOW_USER, settings.SERVICENOW_PASSWORD)


def _adf(text: str) -> dict:
    """Jira Cloud v3 wants Atlassian Document Format, not plain text."""
    return {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]}


async def _request(system: str, method: str, url: str, **kwargs) -> dict:
    try:
        async with _client() as client:
            resp = await client.request(method, url, auth=_auth(system), headers={"Accept": "application/json"}, **kwargs)
    except httpx.HTTPError as exc:
        raise TicketError(502, f"{system} is unreachable: {type(exc).__name__}")
    if resp.status_code == 404:
        raise TicketError(404, f"Ticket not found in {system}")
    if resp.status_code in (401, 403):
        raise TicketError(502, f"{system} rejected the configured credentials")
    if resp.status_code >= 400:
        raise TicketError(502, f"{system} returned HTTP {resp.status_code}")
    try:
        return resp.json() if resp.content else {}
    except ValueError:
        raise TicketError(502, f"{system} returned an unreadable response")


async def fetch_ticket(system: str, key: str) -> TicketInfo:
    key = validate_key(system, key)
    _require(system)
    if system == "jira":
        base = settings.JIRA_BASE_URL.rstrip("/")
        data = await _request("jira", "GET", f"{base}/rest/api/3/issue/{quote(key)}", params={"fields": "status,summary"})
        fields = data.get("fields") or {}
        status = fields.get("status") or {}
        category = (status.get("statusCategory") or {}).get("key", "")
        return TicketInfo(key=key, url=ticket_url("jira", key) or "", external_status=status.get("name", "unknown"),
                          status=_JIRA_CATEGORY.get(category), summary=fields.get("summary", ""))
    base = settings.SERVICENOW_INSTANCE_URL.rstrip("/")
    data = await _request("servicenow", "GET", f"{base}/api/now/table/incident", params={
        "sysparm_query": f"number={key}", "sysparm_limit": "1", "sysparm_fields": "sys_id,number,state,short_description",
        "sysparm_display_value": "false",
    })
    rows = data.get("result") or []
    if not rows:
        raise TicketError(404, "Ticket not found in servicenow")
    row = rows[0]
    state = str(row.get("state", ""))
    return TicketInfo(key=key, url=ticket_url("servicenow", key) or "", external_status=state or "unknown",
                      status=_SERVICENOW_STATE.get(state), summary=row.get("short_description", ""), sys_id=row.get("sys_id"))


async def create_ticket(system: str, title: str, description: str) -> TicketInfo:
    if system not in SYSTEMS:
        raise TicketError(422, f"Unknown ticket system {system!r}; use one of {list(SYSTEMS)}")
    _require(system)
    title = title.strip()[:250] or "Forensiq incident"
    if system == "jira":
        if not settings.JIRA_PROJECT_KEY:
            raise TicketError(503, "JIRA_PROJECT_KEY is not configured, so tickets cannot be created")
        base = settings.JIRA_BASE_URL.rstrip("/")
        data = await _request("jira", "POST", f"{base}/rest/api/3/issue", json={"fields": {
            "project": {"key": settings.JIRA_PROJECT_KEY}, "summary": title,
            "issuetype": {"name": settings.JIRA_ISSUE_TYPE}, "description": _adf(description),
        }})
        key = data.get("key")
        if not key:
            raise TicketError(502, "jira did not return a ticket key")
        return TicketInfo(key=key, url=ticket_url("jira", key) or "", external_status="To Do", status="open", summary=title)
    base = settings.SERVICENOW_INSTANCE_URL.rstrip("/")
    data = await _request("servicenow", "POST", f"{base}/api/now/table/incident",
                          json={"short_description": title, "description": description})
    row = data.get("result") or {}
    key = row.get("number")
    if not key:
        raise TicketError(502, "servicenow did not return a ticket number")
    return TicketInfo(key=key, url=ticket_url("servicenow", key) or "", external_status=str(row.get("state", "1")),
                      status="open", summary=title, sys_id=row.get("sys_id"))


async def push_comment(system: str, key: str, text: str, sys_id: Optional[str] = None) -> None:
    """Best-effort one-way status note onto the external ticket; transitions stay with that system's workflow."""
    key = validate_key(system, key)
    _require(system)
    if system == "jira":
        base = settings.JIRA_BASE_URL.rstrip("/")
        await _request("jira", "POST", f"{base}/rest/api/3/issue/{quote(key)}/comment", json={"body": _adf(text)})
        return
    if not sys_id:
        sys_id = (await fetch_ticket("servicenow", key)).sys_id
    if not sys_id:
        raise TicketError(404, "Ticket not found in servicenow")
    base = settings.SERVICENOW_INSTANCE_URL.rstrip("/")
    await _request("servicenow", "PATCH", f"{base}/api/now/table/incident/{quote(sys_id)}", json={"work_notes": text})
