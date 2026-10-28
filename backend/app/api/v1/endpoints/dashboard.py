from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import DashboardMetrics
from app.api.deps import get_current_user, get_siem_client, require_roles
from app.core.config import settings
from app.core.tenancy import scoped_query, tenant_filter, tenant_id
from app.infrastructure.siem.base import SIEMProvider

router = APIRouter()

# A cycle older than this many poll intervals means the poller is not keeping up (or not running).
STALE_INTERVALS = 4
RECENT_INVESTIGATIONS = 50


def _aware(ts):
    if isinstance(ts, datetime) and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


async def _siem_component(siem: SIEMProvider) -> dict:
    try:
        ok = await siem.authenticate()
    except Exception:
        ok = False
    return {"state": "ok" if ok else "down", "detail": "Splunk authenticated" if ok else "Splunk authentication failed"}


async def _ingestion_component(db, user) -> dict:
    last = await db["ingestion_runs"].find_one(scoped_query(user), sort=[("started_at", -1)])
    if not last:
        return {"state": "never", "detail": "No ingestion cycle has run", "last_run_at": None}
    finished = _aware(last.get("finished_at") or last.get("started_at"))
    age = (datetime.now(timezone.utc) - finished).total_seconds() if finished else None
    if last.get("status") != "ok":
        state, detail = "error", f"Last cycle failed at stage {', '.join(e.get('stage', '?') for e in last.get('errors') or []) or 'unknown'}"
    elif age is not None and age > settings.POLLER_INTERVAL_SECONDS * STALE_INTERVALS:
        state, detail = "stale", f"No cycle for {int(age // 60)} min"
    else:
        state, detail = "ok", f"Fetched {last.get('fetched', 0)} events, {last.get('alerts_new', 0)} new alerts"
    return {
        "state": state, "detail": detail,
        "last_run_at": finished.isoformat() if finished else None,
        "lag_seconds": last.get("lag_seconds"),
    }


async def _threat_intel_component(db, user) -> dict:
    feeds = {"VirusTotal": bool(settings.VT_API_KEY.strip()), "AbuseIPDB": bool(settings.ABUSEIPDB_API_KEY.strip())}
    failing: dict[str, int] = {}
    cursor = db["alerts"].find(
        scoped_query(user, {"status": "Investigated"}), {"enrichments.source": 1, "enrichments.status": 1},
    ).sort("created_at", -1).limit(RECENT_INVESTIGATIONS)
    async for doc in cursor:
        for e in doc.get("enrichments") or []:
            if e.get("status") == "error":
                failing[e.get("source")] = failing.get(e.get("source"), 0) + 1
    details = []
    for name, configured in feeds.items():
        if not configured:
            details.append({"feed": name, "state": "not_configured"})
        elif failing.get(name):
            details.append({"feed": name, "state": "error", "recent_errors": failing[name]})
        else:
            details.append({"feed": name, "state": "ok"})
    states = {d["state"] for d in details}
    state = "ok" if states == {"ok"} else "down" if not any(feeds.values()) else "degraded"
    return {"state": state, "feeds": details}


def _ai_component() -> dict:
    if settings.XAI_API_KEY.strip():
        return {"state": "ok", "mode": "llm", "detail": f"LLM: {settings.XAI_MODEL}"}
    return {"state": "degraded", "mode": "rules", "detail": "No LLM key: risk and recommendations come from the rules engine"}


@router.get("/system-health")
async def system_health(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
    siem: SIEMProvider = Depends(get_siem_client),
):
    """Live status of every dependency the dashboard reports on. No component is assumed healthy."""
    return {
        "siem": await _siem_component(siem),
        "ingestion": await _ingestion_component(db, user),
        "threat_intel": await _threat_intel_component(db, user),
        "ai": _ai_component(),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

@router.get("/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Fetches KPI metrics for the dashboard from MongoDB."""
    scope = tenant_filter(user)
    total_alerts = await db["alerts"].count_documents(scope)
    critical_alerts = await db["alerts"].count_documents(scoped_query(user, {"severity": {"$regex": "^critical$", "$options": "i"}}))
    new_alerts = await db["alerts"].count_documents(scoped_query(user, {"status": "New"}))
    high_priority_alerts = await db["alerts"].count_documents(scoped_query(user, {"severity": {"$in": ["critical", "high"]}, "status": {"$in": ["New", "Investigating"]}}))
    open_investigations = await db["alerts"].count_documents(scoped_query(user, {"status": "Investigating"}))
    investigated_alerts = await db["alerts"].count_documents(scoped_query(user, {"status": "Investigated"}))
    
    if total_alerts > 0:
        pipeline = [{"$match": scope}, {"$group": {"_id": None, "avg_conf": {"$avg": "$ai_confidence"}}}]
        cursor = db["alerts"].aggregate(pipeline)
        result = await cursor.to_list(length=1)
        ai_confidence_avg = int(result[0]["avg_conf"] or 0) if result else 0
    else:
        ai_confidence_avg = 0
        
    org = tenant_id(user)
    ingestion_state = await db["ingestion_state"].find_one({"_id": f"cursor:{org}:splunk"})
    if not ingestion_state and org == "default":
        # Legacy global doc predates tenancy and belongs to the default tenant only.
        ingestion_state = await db["ingestion_state"].find_one({"_id": "last_ingested"})
    last_ingested_at = ingestion_state.get("ts") if ingestion_state else None

    return DashboardMetrics(
        total_alerts=total_alerts,
        new_alerts=new_alerts,
        critical_alerts=critical_alerts,
        high_priority_alerts=high_priority_alerts,
        open_investigations=open_investigations,
        investigated_alerts=investigated_alerts,
        ai_confidence_avg=ai_confidence_avg,
        last_ingested_at=last_ingested_at,
    )


@router.get("/ingestion-health")
async def ingestion_health(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Recent ingestion cycles for the caller's tenant: counts, suppression, errors and lag."""
    runs = []
    cursor = db["ingestion_runs"].find(scoped_query(user)).sort("started_at", -1).limit(20)
    async for run in cursor:
        for key in ("started_at", "finished_at"):
            if hasattr(run.get(key), "isoformat"):
                run[key] = run[key].isoformat()
        # Drop any raw error text (legacy rows stored str(exc)); keep only stage + ref.
        run["errors"] = [{"stage": e.get("stage"), "ref": e.get("ref")} for e in (run.get("errors") or []) if isinstance(e, dict)]
        runs.append(run)
    totals = {
        "fetched": sum(r.get("fetched", 0) for r in runs),
        "suppressed": sum(sum((r.get("suppressed") or {}).values()) for r in runs),
        "alerts_new": sum(r.get("alerts_new", 0) for r in runs),
    }
    return {"last_run": runs[0] if runs else None, "runs": runs, "totals": totals}


@router.get("/config")
async def effective_config(_user: dict = Depends(require_roles("admin"))):
    """Read-only effective configuration (no secrets). Settings change in backend/.env plus a restart."""
    return {
        "siem": {
            "url": settings.SPLUNK_URL,
            "verify_ssl": settings.SPLUNK_VERIFY_SSL,
            "detection_index": settings.SPLUNK_DETECTION_INDEX,
            "allowed_indexes": settings.SPLUNK_ALLOWED_INDEXES,
            "poll_interval_seconds": settings.POLLER_INTERVAL_SECONDS,
        },
        "llm": {
            "configured": bool(settings.XAI_API_KEY.strip()),
            "provider": "xAI",
            "model": settings.XAI_MODEL,
        },
        "threat_intel": {
            "virustotal_configured": bool(settings.VT_API_KEY.strip()),
            "abuseipdb_configured": bool(settings.ABUSEIPDB_API_KEY.strip()),
            "vt_malicious_min_engines": settings.VT_MALICIOUS_MIN_ENGINES,
            "abuseipdb_malicious_min_score": settings.ABUSEIPDB_MALICIOUS_MIN_SCORE,
            "abuseipdb_suspicious_min_score": settings.ABUSEIPDB_SUSPICIOUS_MIN_SCORE,
            "cache_ttl_hours": settings.IOC_CACHE_TTL_HOURS,
        },
        "investigation": {"auto_concurrency": settings.INVESTIGATION_CONCURRENCY},
    }
