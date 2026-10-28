"""
Time-windowed, rarity-weighted, self-excluding correlation service.
Discovers related attacks across entities using rarity scores and temporal windows.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

# Rarity weights: rare indicators / IOCs provide higher correlation confidence
FIELD_WEIGHTS = {
    "extracted_iocs": 30,
    "process_name": 15,
    "command_line": 25,
    "dest_ip": 20,
    "source_ip": 15,
    "user": 10,
    "host": 10,
}

# Common noise values to ignore during correlation matching
COMMON_NOISE_VALUES = {
    "host": {"localhost", "unknown", "127.0.0.1"},
    "user": {"system", "nt authority\\system", "administrator", "-", "unknown", ""},
    "process_name": {"cmd.exe", "powershell.exe", "conhost.exe", "svchost.exe"},
    "source_ip": {"-", "unknown", "127.0.0.1", "0.0.0.0"},
}

DEFAULT_CORRELATION_WINDOW_HOURS = 48


async def correlate_alert(
    db: AsyncIOMotorDatabase,
    alert: dict,
    user: Optional[dict] = None,
    window_hours: int = DEFAULT_CORRELATION_WINDOW_HOURS,
) -> List[dict]:
    """
    Finds correlated historical alerts using a sliding time window,
    rarity-weighted scoring, and excluding common baseline values.
    """
    org = (user or {}).get("org_id", alert.get("org_id", "default"))
    alert_id = str(alert.get("_id", ""))

    # Parse reference time
    created_val = alert.get("created_at")
    if isinstance(created_val, str):
        try:
            ref_dt = datetime.fromisoformat(created_val.replace("Z", "+00:00"))
        except Exception:
            ref_dt = datetime.now(timezone.utc)
    elif isinstance(created_val, datetime):
        ref_dt = created_val if created_val.tzinfo else created_val.replace(tzinfo=timezone.utc)
    else:
        ref_dt = datetime.now(timezone.utc)

    window_start = ref_dt - timedelta(hours=window_hours)
    window_end = ref_dt + timedelta(hours=window_hours)

    # Filter out common values
    match_clauses = []
    active_keys = {}
    for field, weight in FIELD_WEIGHTS.items():
        if field == "extracted_iocs":
            continue
        val = alert.get(field)
        if val and str(val).lower() not in COMMON_NOISE_VALUES.get(field, set()):
            active_keys[field] = val
            match_clauses.append({field: val})

    iocs = [i for i in alert.get("extracted_iocs", []) if i and len(str(i)) > 3]
    if iocs:
        match_clauses.append({"extracted_iocs": {"$in": iocs}})

    if not match_clauses:
        return []

    # Query criteria: same tenant, self-excluding, within sliding time window
    tenant_filter = {"$or": [{"org_id": org}, {"org_id": {"$exists": False}}]} if org == "default" else {"org_id": org}
    
    query = {
        "$and": [
            tenant_filter,
            {"_id": {"$ne": alert_id}},
            {"created_at": {"$gte": window_start, "$lte": window_end}},
            {"$or": match_clauses},
        ]
    }

    cursor = db["alerts"].find(query).sort("created_at", -1).limit(30)
    correlated_results = []

    async for item in cursor:
        matched_factors = []
        score = 0

        for field, target_val in active_keys.items():
            if item.get(field) == target_val:
                weight = FIELD_WEIGHTS.get(field, 10)
                score += weight
                matched_factors.append({"type": field, "value": target_val, "weight": weight})

        shared_iocs = list(set(iocs) & set(item.get("extracted_iocs", [])))
        if shared_iocs:
            ioc_weight = FIELD_WEIGHTS.get("extracted_iocs", 30)
            score += ioc_weight * len(shared_iocs)
            for i in shared_iocs:
                matched_factors.append({"type": "ioc", "value": i, "weight": ioc_weight})

        # Calculate time delta in hours
        item_dt = item.get("created_at")
        if isinstance(item_dt, datetime):
            delta_hrs = abs((ref_dt - (item_dt if item_dt.tzinfo else item_dt.replace(tzinfo=timezone.utc))).total_seconds()) / 3600.0
        else:
            delta_hrs = 0.0

        correlated_results.append({
            "alert_id": str(item.get("_id")),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "host": item.get("host"),
            "created_at": str(item.get("created_at")),
            "correlation_score": min(100, score),
            "time_delta_hours": round(delta_hrs, 1),
            "matches": matched_factors,
        })

    # Sort by correlation strength
    correlated_results.sort(key=lambda x: x["correlation_score"], reverse=True)
    return correlated_results[:20]
