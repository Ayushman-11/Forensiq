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


async def _query_vt(ioc: str, ioc_type: str, db=None) -> Enrichment:
    """Queries VirusTotal API with MongoDB cache lookup."""
    cached = await _get_cached_enrichment(db, ioc, "VirusTotal")
    if cached:
        return cached

    endpoint = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files",
    }.get(ioc_type, "domains")

    if not settings.VT_API_KEY:
        return _unavailable(ioc, ioc_type, "VirusTotal", "not_configured", "VT_API_KEY is not set")

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {"x-apikey": settings.VT_API_KEY, "Accept": "application/json"}

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


async def _query_abuseipdb(ioc: str, db=None) -> Enrichment:
    """Queries AbuseIPDB check API (v2) with MongoDB cache lookup."""
    cached = await _get_cached_enrichment(db, ioc, "AbuseIPDB")
    if cached:
        return cached

    if not settings.ABUSEIPDB_API_KEY:
        return _unavailable(ioc, "ip", "AbuseIPDB", "not_configured", "ABUSEIPDB_API_KEY is not set")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
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

    tasks = []
    for ioc in extracted_iocs:
        ioc_type = _get_ioc_type(ioc)
        # Query VirusTotal for all IOC types
        tasks.append(_query_vt(ioc, ioc_type, db=db))
        # For IP addresses, query AbuseIPDB in parallel
        if ioc_type == "ip":
            tasks.append(_query_abuseipdb(ioc, db=db))

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
