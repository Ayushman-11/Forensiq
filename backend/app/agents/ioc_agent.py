import asyncio
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

async def _query_vt(endpoint: str, ioc: str, ioc_type: str) -> Enrichment:
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
    # simple heuristic mock
    is_malicious = False
    if ioc_type == "ip":
        is_malicious = ioc.startswith("10.") == False and ioc.startswith("192.") == False
    return Enrichment(
        ioc=ioc,
        ioc_type=ioc_type,
        reputation="suspicious" if is_malicious else "benign",
        threat_score=75 if is_malicious else 5,
        source=source,
        raw_response={"mock_reason": "Fallback hit"}
    )

async def enrich_ioc_node(state: AgentState) -> Dict[str, Any]:
    """
    LangGraph node: Takes extracted IOCs from state and enriches them.
    """
    extracted_iocs = state.get("extracted_iocs", [])
    logger.info("ioc_enrichment_start", ioc_count=len(extracted_iocs))
    
    tasks = []
    for ioc in extracted_iocs:
        # crude detection
        if any(c.isalpha() for c in ioc):
            tasks.append(_query_vt("domains", ioc, "domain"))
        else:
            tasks.append(_query_vt("ip_addresses", ioc, "ip"))
            
    results = await asyncio.gather(*tasks)
    
    # Store results as dicts in the state
    enrichment_results = [r.model_dump() for r in results]
    
    logger.info("ioc_enrichment_complete", enriched_count=len(enrichment_results))
    return {"enrichment_results": enrichment_results}
