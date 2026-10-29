"""
Elastic (Elasticsearch / Elastic Security) SIEM provider.

Implements the same SIEMProvider surface as SplunkClient so a tenant can point Forensiq at Elastic instead:
authenticate, search, list_alerts, list_indexes, plus `ingest_query` / `search_raw_pages` for the ingestion
pipeline. Documents are expected in ECS as written by Winlogbeat or the Elastic Agent Windows integration
(`winlog.event_id`, `winlog.event_data.*`, `host.name`, `@timestamp`); `hit_to_row` flattens them into the
Splunk-shaped rows the existing normalisation (`to_canonical`) already understands, so detection rules,
noise policy and incident grouping behave the same whichever SIEM feeds them.

Ingestion pages through a point in time (PIT) with `search_after`, so a large window is read consistently.
Interactive search takes a Lucene query string only (no scripts, no index choice): the indexes come from the
tenant's configuration, not the caller.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import quote

import httpx

from app.core.logging import logger
from app.schemas.normalized_event import NormalizedAlert, NormalizedEvent

ALERT_INDEX = ".alerts-security.alerts-*"
_RELATIVE_RE = re.compile(r"^-(\d+)([smhdw])$")
_EVENT_ID_FIELDS = ("winlog.event_id", "event.code")


def to_es_time(value: str) -> str:
    """Splunk-style '-24h' becomes Elasticsearch date math; 'now' and absolute times pass through."""
    value = (value or "now").strip()
    match = _RELATIVE_RE.match(value)
    if match:
        return f"now-{match.group(1)}{match.group(2)}"
    return value


def _dig(source: dict, dotted: str) -> Any:
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _scalar(value: Any) -> Optional[str]:
    if isinstance(value, list):
        value = next((v for v in value if v not in (None, "")), None)
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value)
    return text if text != "" else None


def hit_to_row(hit: Dict[str, Any]) -> Dict[str, Any]:
    """One Elasticsearch hit as a flat, Splunk-shaped row (`_time`, `EventCode`, `host`, Windows field names)."""
    src = hit.get("_source") or {}
    event_data = _dig(src, "winlog.event_data") or {}
    row: Dict[str, Any] = {k: v for k, v in event_data.items() if _scalar(v) is not None and not isinstance(v, (dict, list))}

    code = _scalar(_dig(src, "winlog.event_id")) or _scalar(_dig(src, "event.code"))
    host = _scalar(_dig(src, "host.name")) or _scalar(_dig(src, "winlog.computer_name"))
    row.update({
        "_time": _scalar(src.get("@timestamp")),
        "_cd": f"{hit.get('_index', '')}:{hit.get('_id', '')}",  # unique per document, so alert ids stay stable across cycles
        "EventCode": code,
        "host": host,
        "Computer": _scalar(_dig(src, "winlog.computer_name")) or host,
        "source": _scalar(_dig(src, "winlog.channel")) or _scalar(_dig(src, "winlog.provider_name")) or "elastic",
    })
    # ECS fallbacks for fields Winlogbeat only puts under process.* / user.* / source.* / destination.*
    fallbacks = {
        "Image": "process.executable", "CommandLine": "process.command_line", "ParentImage": "process.parent.executable",
        "ParentCommandLine": "process.parent.command_line", "ProcessId": "process.pid", "SourceIp": "source.ip", "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port",
    }
    for key, path in fallbacks.items():
        if _scalar(row.get(key)) is None and _scalar(_dig(src, path)) is not None:
            row[key] = _scalar(_dig(src, path))
    if _scalar(row.get("User")) is None and _scalar(_dig(src, "user.name")):
        domain = _scalar(_dig(src, "user.domain"))
        row["User"] = f"{domain}\\{_scalar(_dig(src, 'user.name'))}" if domain else _scalar(_dig(src, "user.name"))
    return {k: v for k, v in row.items() if v is not None}


def hit_to_event(hit: Dict[str, Any]) -> NormalizedEvent:
    row = hit_to_row(hit)
    raw_time = row.get("_time")
    try:
        timestamp = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")) if raw_time else datetime.now(timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    def get(key: str) -> Optional[str]:
        return _scalar(row.get(key))

    def number(key: str) -> Optional[int]:
        value = get(key)
        return int(value) if value and value.isdigit() else None

    return NormalizedEvent(
        timestamp=timestamp, event_id=get("EventCode") or "0", provider="elastic", hostname=get("host") or "unknown",
        user=get("User") or get("TargetUserName") or get("SubjectUserName"), domain=get("TargetDomainName") or get("SubjectDomainName"),
        process_name=get("Image"), command_line=get("CommandLine"), parent_process_name=get("ParentImage"),
        parent_command_line=get("ParentCommandLine"), process_id=number("ProcessId"), parent_process_id=number("ParentProcessId"),
        source_ip=get("SourceIp") or get("IpAddress"), destination_ip=get("DestinationIp"), destination_port=number("DestinationPort"),
        registry_target_object=get("TargetObject"), registry_details=get("Details"), raw_payload=hit.get("_source") or {},
    )


class ElasticClient:
    """Async Elasticsearch REST client implementing SIEMProvider."""

    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        api_key: str = "",
        verify_ssl: bool = True,
        indexes: Optional[List[str]] = None,
    ):
        self.base_url = url.rstrip("/")
        self.username, self.password, self.api_key = username, password, api_key
        self.verify_ssl = verify_ssl
        self.indexes = indexes or ["*"]
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"Accept": "application/json"}
            auth = None
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            elif self.username:
                auth = httpx.BasicAuth(self.username, self.password)
            self._client = httpx.AsyncClient(verify=self.verify_ssl, timeout=httpx.Timeout(30.0, connect=10.0), headers=headers, auth=auth)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        client = await self._get_client()
        resp = await client.request(method, f"{self.base_url}{path}", **kwargs)
        if resp.status_code in (401, 403):
            raise RuntimeError("Elastic rejected the credentials or the key lacks permission")
        if resp.status_code >= 400:
            raise RuntimeError(f"Elastic returned HTTP {resp.status_code}")
        return resp.json() if resp.content else {}

    async def authenticate(self) -> bool:
        """The cluster root answers 200 only to a valid credential."""
        try:
            info = await self._request("GET", "/")
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Elastic Authentication Failed: {type(exc).__name__}")
        except RuntimeError as exc:
            raise RuntimeError(f"Elastic Authentication Failed: {exc}")
        logger.info("elastic_auth_success", cluster=info.get("cluster_name"))
        return True

    # -- ingestion ---------------------------------------------------------

    def ingest_query(self, index: str, event_codes: tuple) -> dict:
        """The provider-specific form of 'the events ingestion needs'. Ingestion passes it back to search_raw_pages."""
        return {"index": index, "event_codes": [str(c) for c in event_codes]}

    async def search_raw_pages(
        self,
        query: Dict[str, Any],
        earliest_time: str,
        latest_time: str = "now",
        page_size: int = 500,
        max_pages: int = 20,
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Reads events oldest first through a point in time, yielding Splunk-shaped rows page by page."""
        index, codes = query["index"], query["event_codes"]
        pit = (await self._request("POST", f"/{quote(index, safe='*,-_.')}/_pit", params={"keep_alive": "2m"})).get("id")
        if not pit:
            raise RuntimeError("Elastic did not open a point in time")
        time_range = {"gte": earliest_time, "format": "epoch_second", "lte": to_es_time(latest_time)}
        base_body: Dict[str, Any] = {
            "size": page_size, "track_total_hits": False, "pit": {"id": pit, "keep_alive": "2m"},
            "sort": [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": time_range}},
                {"bool": {"should": [{"terms": {field: codes}} for field in _EVENT_ID_FIELDS], "minimum_should_match": 1}},
            ]}},
        }
        try:
            search_after = None
            for _ in range(max_pages):
                body = dict(base_body)
                if search_after:
                    body["search_after"] = search_after
                data = await self._request("POST", "/_search", json=body)
                hits = (data.get("hits") or {}).get("hits") or []
                if not hits:
                    return
                yield [hit_to_row(h) for h in hits]
                if len(hits) < page_size:
                    return
                search_after = hits[-1].get("sort")
                pit = data.get("pit_id") or pit
                base_body["pit"] = {"id": pit, "keep_alive": "2m"}
        finally:
            try:
                await self._request("DELETE", "/_pit", json={"id": pit})
            except Exception as exc:  # the PIT expires on its own; never fail a cycle over cleanup
                logger.warning("elastic_pit_close_failed", error=str(exc))

    # -- interactive search and metadata -----------------------------------

    async def search(self, query: str, earliest_time: str = "-24h", latest_time: str = "now", limit: int = 100) -> List[NormalizedEvent]:
        """Lucene query string over the tenant's configured indexes. No scripting, no caller-chosen index."""
        body = {
            "size": max(1, min(limit, 1000)), "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {
                "must": [{"query_string": {"query": query, "default_operator": "AND", "allow_leading_wildcard": False, "analyze_wildcard": False}}],
                "filter": [{"range": {"@timestamp": {"gte": to_es_time(earliest_time), "lte": to_es_time(latest_time)}}}],
            }},
        }
        index = ",".join(quote(i, safe="*-_.") for i in self.indexes)
        data = await self._request("POST", f"/{index}/_search", json=body, params={"ignore_unavailable": "true"})
        return [hit_to_event(h) for h in (data.get("hits") or {}).get("hits") or []]

    async def list_alerts(self, limit: int = 50) -> List[NormalizedAlert]:
        """Elastic Security detection alerts."""
        try:
            data = await self._request("POST", f"/{ALERT_INDEX}/_search", params={"ignore_unavailable": "true"},
                                       json={"size": max(1, min(limit, 500)), "sort": [{"@timestamp": "desc"}], "query": {"match_all": {}}})
        except RuntimeError:
            return []
        alerts: List[NormalizedAlert] = []
        for hit in (data.get("hits") or {}).get("hits") or []:
            src = hit.get("_source") or {}
            created = _scalar(src.get("@timestamp"))
            try:
                created_at = datetime.fromisoformat(created.replace("Z", "+00:00")) if created else datetime.now(timezone.utc)
            except ValueError:
                created_at = datetime.now(timezone.utc)
            flat = {k: v for k, v in src.items() if k.startswith("kibana.alert")}
            alerts.append(NormalizedAlert(
                alert_id=str(hit.get("_id")), title=_scalar(src.get("kibana.alert.rule.name")) or "Elastic alert",
                description=_scalar(src.get("kibana.alert.reason")), severity=(_scalar(src.get("kibana.alert.severity")) or "medium").lower(),
                created_at=created_at, source_siem="elastic", affected_hostname=_scalar(_dig(src, "host.name")),
                affected_user=_scalar(_dig(src, "user.name")), raw_alert_data=flat,
            ))
        return alerts

    async def list_indexes(self) -> List[str]:
        data = await self._request("GET", "/_cat/indices", params={"format": "json", "h": "index"})
        rows: List[Dict[str, Any]] = data if isinstance(data, list) else []
        return sorted(row["index"] for row in rows if row.get("index"))
