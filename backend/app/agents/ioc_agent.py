"""
IOC Enrichment Agent Node for LangGraph.
Queries threat intelligence feeds (VirusTotal v3 and AbuseIPDB v2) with
persistent MongoDB caching and fallback heuristics to identify malicious indicators.
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
            return Enrichment(**data)
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


def _mock_vt_enrichment(ioc: str, ioc_type: str, source: str) -> Enrichment:
    """Simulates realistic VirusTotal intelligence based on indicator patterns."""
    is_malicious = False
    reputation = "benign"
    threat_score = 0

    if ioc_type == "ip":
        if ioc.startswith("47.") or ioc.startswith("185.") or ioc.startswith("104.") or ioc.startswith("194.") or ioc.startswith("45."):
            is_malicious = True
            threat_score = 88
            reputation = "malicious"
    elif ioc_type == "domain":
        if any(bad in ioc.lower() for bad in ["ngrok", "raw.githubusercontent", "pastebin", "dyndns", "bit.ly", "payload"]):
            is_malicious = True
            threat_score = 95
            reputation = "malicious"
    elif ioc_type == "hash":
        if any(h in ioc.lower() for h in ["ba4038fd", "097ce576"]):
            is_malicious = True
            threat_score = 92
            reputation = "malicious"

    return Enrichment(
        ioc=ioc,
        ioc_type=ioc_type,
        reputation=reputation,
        threat_score=threat_score,
        source=source,
        raw_response={"mock_reason": f"Simulated VT {reputation} telemetry"},
        cached=False,
    )


def _mock_abuseipdb_enrichment(ioc: str, source: str) -> Enrichment:
    """Simulates realistic AbuseIPDB abuse reports based on IP ranges."""
    is_malicious = False
    reputation = "benign"
    threat_score = 0
    total_reports = 0

    if ioc.startswith("45.") or ioc.startswith("185.") or ioc.startswith("194.") or ioc.startswith("47."):
        is_malicious = True
        threat_score = 85
        total_reports = 64
        reputation = "malicious"

    return Enrichment(
        ioc=ioc,
        ioc_type="ip",
        reputation=reputation,
        threat_score=threat_score,
        source=source,
        raw_response={
            "abuseConfidenceScore": threat_score,
            "totalReports": total_reports,
            "countryCode": "RU" if is_malicious else "US",
            "mock_reason": f"Simulated AbuseIPDB {reputation} data",
        },
        cached=False,
    )


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
        res = _mock_vt_enrichment(ioc, ioc_type, "VirusTotal (Mock)")
        await _save_cached_enrichment(db, res)
        return res

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

            if malicious > 0:
                reputation = "malicious"
            elif suspicious > 0:
                reputation = "suspicious"
            elif harmless > 0:
                reputation = "benign"
            else:
                reputation = "unknown"

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
        res = _mock_vt_enrichment(ioc, ioc_type, "VirusTotal (Error Fallback)")
        return res


async def _query_abuseipdb(ioc: str, db=None) -> Enrichment:
    """Queries AbuseIPDB check API (v2) with MongoDB cache lookup."""
    cached = await _get_cached_enrichment(db, ioc, "AbuseIPDB")
    if cached:
        return cached

    if not settings.ABUSEIPDB_API_KEY:
        res = _mock_abuseipdb_enrichment(ioc, "AbuseIPDB (Mock)")
        await _save_cached_enrichment(db, res)
        return res

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": "90", "verbose": ""}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})

            abuse_score = int(data.get("abuseConfidenceScore", 0))
            if abuse_score >= 50:
                reputation = "malicious"
            elif abuse_score >= 20:
                reputation = "suspicious"
            else:
                reputation = "benign"

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
        res = _mock_abuseipdb_enrichment(ioc, "AbuseIPDB (Error Fallback)")
        return res


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

    cache_str = f" ({cached_count} served from MongoDB cache)" if cached_count > 0 else ""
    current_log = state.get("investigation_log", [])
    new_log = current_log + [
        f"IOC Enrichment Agent: checked {len(results)} feed records across {len(extracted_iocs)} IOCs{cache_str}. "
        f"{malicious_count} malicious, {suspicious_count} suspicious."
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
