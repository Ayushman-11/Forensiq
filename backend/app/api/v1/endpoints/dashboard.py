from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.session import get_db
from app.models.alert import DashboardMetrics
from app.api.deps import get_current_user, get_siem_client, require_roles
from app.core.config import settings
from app.core.timeutil import iso_utc
from app.core.tenancy import scoped_query, tenant_filter, tenant_id
from app.infrastructure.siem.base import SIEMProvider
from app.services.sla import get_sla_targets
from app.services.tenants import resolve_config
from app.services.triage import OPEN_STATUSES, detected_at, sla_state

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
        "last_run_at": iso_utc(finished) if finished else None,
        "lag_seconds": last.get("lag_seconds"),
    }


async def _threat_intel_component(db, user) -> dict:
    tenant = await resolve_config(db, tenant_id(user))
    feeds = {"VirusTotal": bool(tenant.vt_api_key), "AbuseIPDB": bool(tenant.abuseipdb_api_key)}
    # Optional feeds appear only once configured; an unset one is not a gap in coverage.
    for name, configured in (("OTX", tenant.otx_api_key), ("GreyNoise", tenant.greynoise_api_key), ("MISP", tenant.misp_api_key)):
        if configured:
            feeds[name] = True
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
    high_priority_alerts = await db["alerts"].count_documents(scoped_query(user, {"severity": {"$in": ["critical", "high"]}, "status": {"$in": list(OPEN_STATUSES)}}))
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
                run[key] = iso_utc(run[key])
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
async def effective_config(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(require_roles("admin"))):
    """Read-only effective configuration of the caller's tenant (no secrets). Tenant settings: /tenants/current/settings."""
    tenant = await resolve_config(db, tenant_id(user))
    return {
        "siem": {
            "url": tenant.siem.url,
            "verify_ssl": tenant.siem.verify_ssl,
            "detection_index": tenant.siem.detection_index,
            "allowed_indexes": tenant.siem.allowed_indexes,
            "poll_interval_seconds": tenant.siem.poll_interval_seconds,
        },
        "llm": {
            "configured": bool(settings.XAI_API_KEY.strip()),
            "provider": "xAI",
            "model": settings.XAI_MODEL,
        },
        "threat_intel": {
            "virustotal_configured": bool(tenant.vt_api_key),
            "abuseipdb_configured": bool(tenant.abuseipdb_api_key),
            "vt_malicious_min_engines": settings.VT_MALICIOUS_MIN_ENGINES,
            "abuseipdb_malicious_min_score": settings.ABUSEIPDB_MALICIOUS_MIN_SCORE,
            "abuseipdb_suspicious_min_score": settings.ABUSEIPDB_SUSPICIOUS_MIN_SCORE,
            "cache_ttl_hours": settings.IOC_CACHE_TTL_HOURS,
        },
        "investigation": {"auto_concurrency": settings.INVESTIGATION_CONCURRENCY},
    }


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


@router.get("/soc-metrics")
async def soc_metrics(
    days: int = Query(7, ge=1, le=90),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Analyst-workflow metrics computed from triage timestamps and verdicts.

    MTTA = detection to first human action (assign, note or disposition); MTTR = detection to
    close/suppress. Rule precision = true positives / (true + false positives) among closed alerts.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    fields = {"severity": 1, "status": 1, "rule_name": 1, "verdict": 1, "assignee_id": 1,
              "detected_at": 1, "created_at": 1, "acknowledged_at": 1, "resolved_at": 1}
    ack_minutes, resolve_minutes = [], []
    open_by_severity: dict[str, int] = {}
    aging = {"lt_1h": 0, "1h_24h": 0, "1d_7d": 0, "gt_7d": 0}
    verdicts: dict[str, int] = {}
    rules: dict[str, dict] = {}
    unassigned_open = ack_breached = resolve_breached = 0

    sla_targets = await get_sla_targets(db, tenant_id(user))
    cursor = db["alerts"].find(scoped_query(user), fields)
    async for a in cursor:
        start = detected_at(a)
        status = a.get("status")
        if status in OPEN_STATUSES:
            sev = str(a.get("severity") or "unknown").lower()
            open_by_severity[sev] = open_by_severity.get(sev, 0) + 1
            if not a.get("assignee_id"):
                unassigned_open += 1
            sla = sla_state(a, now, sla_targets)
            if sla:
                ack_breached += sla["ack_breached"]
                resolve_breached += sla["resolve_breached"]
            if start:
                age_h = (now - start).total_seconds() / 3600
                bucket = "lt_1h" if age_h < 1 else "1h_24h" if age_h < 24 else "1d_7d" if age_h < 168 else "gt_7d"
                aging[bucket] += 1
        if not start or start < since:
            continue
        acked, resolved = _aware(a.get("acknowledged_at")), _aware(a.get("resolved_at"))
        if acked:
            ack_minutes.append((acked - start).total_seconds() / 60)
        if resolved:
            resolve_minutes.append((resolved - start).total_seconds() / 60)
        verdict = a.get("verdict")
        if verdict:
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            rule = rules.setdefault(a.get("rule_name") or "unknown", {"rule": a.get("rule_name") or "unknown", "closed": 0, "true_positive": 0, "false_positive": 0})
            rule["closed"] += 1
            if verdict in ("true_positive", "false_positive"):
                rule[verdict] += 1

    for rule in rules.values():
        decided = rule["true_positive"] + rule["false_positive"]
        rule["precision"] = round(rule["true_positive"] / decided, 3) if decided else None

    def _round(v):
        return round(v, 1) if v is not None else None

    return {
        "window_days": days,
        "mtta_minutes": _round(_median(ack_minutes)),
        "mttr_minutes": _round(_median(resolve_minutes)),
        "acknowledged": len(ack_minutes),
        "resolved": len(resolve_minutes),
        "open_by_severity": open_by_severity,
        "unassigned_open": unassigned_open,
        "sla_breached": {"acknowledge": ack_breached, "resolve": resolve_breached},
        "open_aging": aging,
        "verdicts": verdicts,
        "rule_precision": sorted(rules.values(), key=lambda r: (r["precision"] is None, r["precision"] or 0)),
    }
