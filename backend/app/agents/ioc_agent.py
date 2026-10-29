"""
IOC Enrichment Agent Node for LangGraph.
Queries threat intelligence feeds (VirusTotal v3 and AbuseIPDB v2) with
persistent MongoDB caching. A feed that is unconfigured or failing yields no verdict,
never a simulated one.
"""

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import httpx
from app.core.logging import logger
from app.core.config import settings
from app.agents.state import AgentState
from app.database.session import get_db


class Enrichment(BaseModel):
    ioc: str
    ioc_type: str  # 'ip', 'domain', 'hash'
    reputation: str  # 'malicious', 'suspicious', 'benign', 'unknown'
    threat_score: int  # 0-100
    source: str
    raw_response: dict
    cached: bool = False
    # ok: the feed answered. not_configured / error: no verdict exists, so the
    # result must not raise risk, be cached, or be shown as a reputation.
    status: str = "ok"


def _get_ioc_type(ioc: str) -> str:
    """Classifies an indicator string as ip, hash, or domain."""
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "hash"
    return "domain"


async def _get_cached_enrichment(db, ioc: str, source: str) -> Optional[Enrichment]:
    """Retrieves valid cached enrichment from MongoDB ioc_cache collection if unexpired."""
    if db is None:
        return None
    try:
        doc = await db["ioc_cache"].find_one({"ioc": ioc, "source": source})
        if not doc:
            return None
        cached_at = doc.get("cached_at")
        if cached_at:
            if isinstance(cached_at, datetime):
                age = datetime.now(timezone.utc) - (cached_at if cached_at.tzinfo else cached_at.replace(tzinfo=timezone.utc))
                if age > timedelta(hours=settings.IOC_CACHE_TTL_HOURS):
                    return None
            data = doc.get("data", {})
            data["cached"] = True
            enrichment = Enrichment(**data)
            if enrichment.status != "ok":
                return None
            # Re-derive the verdict so threshold changes apply to cached entries too.
            raw = enrichment.raw_response or {}
            if source == "VirusTotal":
                enrichment.reputation = _vt_verdict(raw)
            elif source == "OTX" and "pulse_count" in raw:
                enrichment.reputation = _otx_verdict(int(raw["pulse_count"]))
            elif source == "AbuseIPDB" and "abuseConfidenceScore" in raw:
                enrichment.reputation = _abuseipdb_verdict(int(raw["abuseConfidenceScore"]))
            return enrichment
    except Exception as e:
        logger.warning("ioc_cache_read_error", ioc=ioc, source=source, error=str(e))
    return None


async def _save_cached_enrichment(db, enrichment: Enrichment) -> None:
    """Persists enrichment result into MongoDB ioc_cache collection."""
    if db is None:
        return
    try:
        await db["ioc_cache"].update_one(
            {"ioc": enrichment.ioc, "source": enrichment.source},
            {
                "$set": {
                    "data": enrichment.model_dump(),
                    "cached_at": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )
    except Exception as e:
        logger.warning("ioc_cache_write_error", ioc=enrichment.ioc, source=enrichment.source, error=str(e))


def _unavailable(ioc: str, ioc_type: str, source: str, status: str, reason: str) -> Enrichment:
    """A feed that could not be consulted: no verdict, and never cached or counted as evidence."""
    return Enrichment(
        ioc=ioc,
        ioc_type=ioc_type,
        reputation="unknown",
        threat_score=0,
        source=source,
        raw_response={"reason": reason},
        status=status,
    )


def _vt_verdict(stats: dict) -> str:
    """One stray engine is noise; only a quorum of engines makes an IOC malicious."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= settings.VT_MALICIOUS_MIN_ENGINES:
        return "malicious"
    if malicious > 0 or suspicious > 0:
        return "suspicious"
    if stats.get("harmless", 0) > 0:
        return "benign"
    return "unknown"


def _abuseipdb_verdict(score: int) -> str:
    if score >= settings.ABUSEIPDB_MALICIOUS_MIN_SCORE:
        return "malicious"
    if score >= settings.ABUSEIPDB_SUSPICIOUS_MIN_SCORE:
        return "suspicious"
    return "benign"


async def _query_vt(ioc: str, ioc_type: str, db=None, api_key: str | None = None) -> Enrichment:
    """Queries VirusTotal API with MongoDB cache lookup."""
    cached = await _get_cached_enrichment(db, ioc, "VirusTotal")
    if cached:
        return cached

    endpoint = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files",
    }.get(ioc_type, "domains")

    api_key = settings.VT_API_KEY if api_key is None else api_key  # the tenant's key; global only when no tenant resolved
    if not api_key:
        return _unavailable(ioc, ioc_type, "VirusTotal", "not_configured", "VT_API_KEY is not set")

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total = malicious + suspicious + harmless + undetected
            threat_score = int((malicious / total) * 100) if total > 0 else 0

            reputation = _vt_verdict(stats)

            res = Enrichment(
                ioc=ioc,
                ioc_type=ioc_type,
                reputation=reputation,
                threat_score=threat_score,
                source="VirusTotal",
                raw_response=stats,
                cached=False,
            )
            await _save_cached_enrichment(db, res)
            return res
    except Exception as e:
        logger.error("vt_api_error", ioc=ioc, error=str(e))
        return _unavailable(ioc, ioc_type, "VirusTotal", "error", type(e).__name__)


async def _query_abuseipdb(ioc: str, db=None, api_key: str | None = None) -> Enrichment:
    """Queries AbuseIPDB check API (v2) with MongoDB cache lookup."""
    cached = await _get_cached_enrichment(db, ioc, "AbuseIPDB")
    if cached:
        return cached

    api_key = settings.ABUSEIPDB_API_KEY if api_key is None else api_key
    if not api_key:
        return _unavailable(ioc, "ip", "AbuseIPDB", "not_configured", "ABUSEIPDB_API_KEY is not set")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": "90", "verbose": ""}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})

            abuse_score = int(data.get("abuseConfidenceScore", 0))
            reputation = _abuseipdb_verdict(abuse_score)

            res = Enrichment(
                ioc=ioc,
                ioc_type="ip",
                reputation=reputation,
                threat_score=abuse_score,
                source="AbuseIPDB",
                raw_response={
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": data.get("totalReports", 0),
                    "countryCode": data.get("countryCode"),
                    "domain": data.get("domain"),
                    "isp": data.get("isp"),
                },
                cached=False,
            )
            await _save_cached_enrichment(db, res)
            return res
    except Exception as e:
        logger.error("abuseipdb_api_error", ioc=ioc, error=str(e))
        return _unavailable(ioc, "ip", "AbuseIPDB", "error", type(e).__name__)


def _http(timeout: float = 10.0, verify: bool = True) -> httpx.AsyncClient:
    """Indirection so tests can inject a mock transport. Redirects are off: a feed must answer where it was asked."""
    return httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=verify)


def _otx_verdict(pulses: int) -> str:
    """OTX pulses are community-written and noisy: one pulse is a hint, a quorum is a verdict. Absence proves nothing."""
    if pulses >= settings.OTX_MALICIOUS_MIN_PULSES:
        return "malicious"
    if pulses >= settings.OTX_SUSPICIOUS_MIN_PULSES:
        return "suspicious"
    return "unknown"


async def _query_otx(ioc: str, ioc_type: str, db=None, api_key: str | None = None) -> Enrichment:
    """AlienVault OTX indicator lookup (public intelligence, so shared in the cache)."""
    cached = await _get_cached_enrichment(db, ioc, "OTX")
    if cached:
        return cached
    api_key = settings.OTX_API_KEY if api_key is None else api_key
    if not api_key:
        return _unavailable(ioc, ioc_type, "OTX", "not_configured", "OTX_API_KEY is not set")
    kind = {"ip": "IPv6" if ":" in ioc else "IPv4", "domain": "domain", "hash": "file"}.get(ioc_type, "domain")
    try:
        async with _http() as client:
            resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ioc}/general", headers={"X-OTX-API-KEY": api_key})
            if resp.status_code == 404:  # not known to OTX is a clean "no information", not a failure
                data = {}
            else:
                resp.raise_for_status()
                data = resp.json()
        pulse_info = data.get("pulse_info") or {}
        count = int(pulse_info.get("count", 0))
        res = Enrichment(
            ioc=ioc, ioc_type=ioc_type, reputation=_otx_verdict(count), threat_score=min(100, count * 10), source="OTX",
            raw_response={"pulse_count": count, "pulses": [str(p.get("name", ""))[:100] for p in (pulse_info.get("pulses") or [])[:5]]},
        )
        await _save_cached_enrichment(db, res)
        return res
    except Exception as e:
        logger.error("otx_api_error", ioc=ioc, error=str(e))
        return _unavailable(ioc, ioc_type, "OTX", "error", type(e).__name__)


def _greynoise_verdict(data: dict) -> str:
    """RIOT = a well-known benign service. Classified malicious = known bad. Mass-scanning noise alone is only a hint."""
    if data.get("classification") == "malicious":
        return "malicious"
    if data.get("riot") or data.get("classification") == "benign":
        return "benign"
    if data.get("noise"):
        return "suspicious"
    return "unknown"


async def _query_greynoise(ioc: str, db=None, api_key: str | None = None) -> Enrichment:
    """GreyNoise community lookup, IPv4 only. Its main value is saying an address is background internet noise or a benign service."""
    cached = await _get_cached_enrichment(db, ioc, "GreyNoise")
    if cached:
        return cached
    api_key = settings.GREYNOISE_API_KEY if api_key is None else api_key
    if not api_key:
        return _unavailable(ioc, "ip", "GreyNoise", "not_configured", "GREYNOISE_API_KEY is not set")
    try:
        async with _http() as client:
            resp = await client.get(f"https://api.greynoise.io/v3/community/{ioc}", headers={"key": api_key, "Accept": "application/json"})
            if resp.status_code == 404:  # "not observed" is an answer
                data = {}
            else:
                resp.raise_for_status()
                data = resp.json()
        verdict = _greynoise_verdict(data)
        res = Enrichment(
            ioc=ioc, ioc_type="ip", reputation=verdict, threat_score={"malicious": 90, "suspicious": 40}.get(verdict, 0), source="GreyNoise",
            raw_response={"classification": data.get("classification"), "noise": bool(data.get("noise")), "riot": bool(data.get("riot")),
                          "name": str(data.get("name") or "")[:100], "last_seen": data.get("last_seen")},
        )
        await _save_cached_enrichment(db, res)
        return res
    except Exception as e:
        logger.error("greynoise_api_error", ioc=ioc, error=str(e))
        return _unavailable(ioc, "ip", "GreyNoise", "error", type(e).__name__)


async def _query_misp(ioc: str, ioc_type: str, url: str, api_key: str) -> Enrichment:
    """
    Search the tenant's own MISP. NEVER cached: the cache is shared across tenants and this is one tenant's
    private intelligence. MISP warning lists are enforced so benign infrastructure does not match.
    """
    if not (url and api_key):
        return _unavailable(ioc, ioc_type, "MISP", "not_configured", "MISP is not configured")
    try:
        async with _http(timeout=15.0, verify=settings.MISP_VERIFY_SSL) as client:
            resp = await client.post(
                f"{url.rstrip('/')}/attributes/restSearch",
                headers={"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"},
                json={"returnFormat": "json", "value": ioc, "limit": 25, "enforceWarninglist": True},
            )
            resp.raise_for_status()
            attributes = ((resp.json().get("response") or {}).get("Attribute")) or []
        actionable = [a for a in attributes if a.get("to_ids")]
        verdict = "malicious" if actionable else ("suspicious" if attributes else "unknown")
        return Enrichment(
            ioc=ioc, ioc_type=ioc_type, reputation=verdict, threat_score={"malicious": 90, "suspicious": 40}.get(verdict, 0), source="MISP",
            raw_response={"attribute_count": len(attributes), "actionable": len(actionable),
                          "event_ids": sorted({str(a.get("event_id")) for a in attributes})[:5]},
        )
    except Exception as e:
        logger.error("misp_api_error", ioc=ioc, error=str(e))
        return _unavailable(ioc, ioc_type, "MISP", "error", type(e).__name__)


async def enrich_ioc_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Asynchronously queries VirusTotal and AbuseIPDB
    for all extracted IOCs with persistent MongoDB cache optimization.
    """
    extracted_iocs = state.get("extracted_iocs", [])
    logger.info("ioc_enrichment_start", ioc_count=len(extracted_iocs))

    db = None
    try:
        db = await get_db()
    except Exception as e:
        logger.warning("ioc_enrichment_db_unavailable", error=str(e))

    # Each tenant enriches with its own feed keys (or the platform's, if the operator allows it), never another tenant's.
    vt_key = abuse_key = None
    otx_key, greynoise_key, misp_url, misp_key = settings.OTX_API_KEY, settings.GREYNOISE_API_KEY, settings.MISP_URL, settings.MISP_API_KEY
    if db is not None:
        org_id = (state.get("alert_data") or {}).get("org_id", "default")
        try:
            from app.services.tenants import threat_intel_config

            ti = await threat_intel_config(db, org_id)
            vt_key, abuse_key = ti["virustotal"], ti["abuseipdb"]
            otx_key, greynoise_key, misp_url, misp_key = ti["otx"], ti["greynoise"], ti["misp_url"], ti["misp_key"]
        except Exception as e:
            logger.warning("tenant_threat_intel_keys_unavailable", org_id=org_id, error=str(e))
            vt_key = abuse_key = ""  # fail closed: no verdict rather than someone else's key
            otx_key = greynoise_key = misp_url = misp_key = ""

    tasks = []
    for ioc in extracted_iocs:
        ioc_type = _get_ioc_type(ioc)
        # Query VirusTotal for all IOC types
        tasks.append(_query_vt(ioc, ioc_type, db=db, api_key=vt_key))
        # For IP addresses, query AbuseIPDB in parallel
        if ioc_type == "ip":
            tasks.append(_query_abuseipdb(ioc, db=db, api_key=abuse_key))
        # Optional feeds are only asked when configured, so an unconfigured one adds no noise to the result.
        if otx_key:
            tasks.append(_query_otx(ioc, ioc_type, db=db, api_key=otx_key))
        if greynoise_key and ioc_type == "ip" and ":" not in ioc:
            tasks.append(_query_greynoise(ioc, db=db, api_key=greynoise_key))
        if misp_url and misp_key:
            tasks.append(_query_misp(ioc, ioc_type, misp_url, misp_key))

    results: List[Enrichment] = []
    if tasks:
        results = await asyncio.gather(*tasks)

    enrichment_results = [r.model_dump() for r in results]

    malicious_count = sum(1 for r in results if r.reputation == "malicious")
    suspicious_count = sum(1 for r in results if r.reputation == "suspicious")
    cached_count = sum(1 for r in results if r.cached)
    unavailable = sorted({f"{r.source} ({r.status})" for r in results if r.status != "ok"})

    cache_str = f" ({cached_count} served from MongoDB cache)" if cached_count > 0 else ""
    gap_str = f" No verdict from: {', '.join(unavailable)}." if unavailable else ""
    current_log = state.get("investigation_log", [])
    new_log = current_log + [
        f"IOC Enrichment Agent: checked {len(results)} feed records across {len(extracted_iocs)} IOCs{cache_str}. "
        f"{malicious_count} malicious, {suspicious_count} suspicious.{gap_str}"
    ]

    logger.info(
        "ioc_enrichment_complete",
        total_queries=len(results),
        cached_count=cached_count,
        malicious=malicious_count,
    )

    return {
        "enrichment_results": enrichment_results,
        "investigation_log": new_log,
    }
