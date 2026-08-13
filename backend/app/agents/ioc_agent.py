import asyncio
import re
from typing import List, Dict, Any
from pydantic import BaseModel
import httpx
from app.core.logging import logger
from app.core.config import settings
from app.agents.state import AgentState

class Enrichment(BaseModel):
    ioc: str
    ioc_type: str # 'ip', 'domain', 'hash'
    reputation: str # 'malicious', 'suspicious', 'benign', 'unknown'
    threat_score: int # 0-100
    source: str
    raw_response: dict
    cached: bool = False

def _get_ioc_type(ioc: str) -> str:
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "hash"
    return "domain"

async def _query_vt(ioc: str, ioc_type: str) -> Enrichment:
    endpoint = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files"
    }.get(ioc_type, "domains")
    
    if not settings.VT_API_KEY:
        return _mock_enrichment(ioc, ioc_type, "VirusTotal (Mock)")
        
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {
        "x-apikey": settings.VT_API_KEY,
        "Accept": "application/json"
    }
    
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
                
            return Enrichment(
                ioc=ioc,
                ioc_type=ioc_type,
                reputation=reputation,
                threat_score=threat_score,
                source="VirusTotal",
                raw_response=stats
            )
    except Exception as e:
        logger.error("vt_api_error", ioc=ioc, error=str(e))
        return _mock_enrichment(ioc, ioc_type, "VirusTotal (Error Fallback)")

def _mock_enrichment(ioc: str, ioc_type: str, source: str) -> Enrichment:
    # advanced heuristic mock based on common bad patterns
    is_malicious = False
    reputation = "benign"
    threat_score = 0
    
    if ioc_type == "ip":
        # Simulate some IPs as malicious
        if ioc.startswith("47.") or ioc.startswith("185.") or ioc.startswith("104.") or ioc.startswith("34."):
            is_malicious = True
            threat_score = 85
            reputation = "malicious"
    elif ioc_type == "domain":
        if any(bad in ioc.lower() for bad in ["ngrok", "raw.githubusercontent", "pastebin", "dyndns", "bit.ly"]):
            is_malicious = True
            threat_score = 95
            reputation = "malicious"
            
    return Enrichment(
        ioc=ioc,
        ioc_type=ioc_type,
        reputation=reputation,
        threat_score=threat_score,
        source=source,
        raw_response={"mock_reason": f"Simulated {reputation} result"}
    )

async def enrich_ioc_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Takes extracted IOCs from state and enriches them.
    """
    extracted_iocs = state.get("extracted_iocs", [])
    logger.info("ioc_enrichment_start", ioc_count=len(extracted_iocs))
    
    tasks = []
    for ioc in extracted_iocs:
        ioc_type = _get_ioc_type(ioc)
        tasks.append(_query_vt(ioc, ioc_type))
            
    results = await asyncio.gather(*tasks)
    
    enrichment_results = [r.model_dump() for r in results]
    
    malicious_count = sum(1 for r in results if r.reputation == "malicious")
    suspicious_count = sum(1 for r in results if r.reputation == "suspicious")
    
    current_log = state.get("investigation_log", [])
    new_log = current_log + [f"IOC Enrichment complete: {len(results)} IOCs checked. {malicious_count} malicious, {suspicious_count} suspicious."]
    
    logger.info("ioc_enrichment_complete", enriched_count=len(enrichment_results))
    
    return {
        "enrichment_results": enrichment_results,
        "investigation_log": new_log
    }
