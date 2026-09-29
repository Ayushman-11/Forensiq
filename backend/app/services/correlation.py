from datetime import datetime

FIELDS = ("host", "user", "source_ip", "dest_ip", "process_name")

async def correlate_alert(db, alert: dict, user: dict | None = None) -> list[dict]:
    org = (user or {}).get("org_id", alert.get("org_id", "default"))
    keys = {field: alert.get(field) for field in FIELDS if alert.get(field) not in (None, "", "Unknown")}
    iocs = [value for value in alert.get("extracted_iocs", []) if value]
    clauses = [{field: value} for field, value in keys.items()]
    if iocs:
        clauses.append({"extracted_iocs": {"$in": iocs}})
    if not clauses:
        return []
    tenant = {"$or": [{"org_id": org}, {"org_id": {"$exists": False}}]} if org == "default" else {"org_id": org}
    query = {"$and": [tenant, {"_id": {"$ne": alert.get("_id")}}, {"$or": clauses}]}
    cursor = db["alerts"].find(query).sort("created_at", -1).limit(25)
    results = []
    async for item in cursor:
        matches = []
        for field, value in keys.items():
            if item.get(field) == value:
                matches.append({"type": field, "value": value})
        common_iocs = sorted(set(iocs) & set(item.get("extracted_iocs", [])))
        matches.extend({"type": "ioc", "value": value} for value in common_iocs)
        results.append({
            "alert_id": str(item.get("_id")), "title": item.get("title"),
            "severity": item.get("severity"), "status": item.get("status"),
            "created_at": item.get("created_at"), "matches": matches,
        })
    return results
