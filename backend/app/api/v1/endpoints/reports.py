"""
Report Generation Endpoints.
Provides PDF download endpoints for full investigation reports and executive summaries.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.api.deps import get_current_user
from app.core.tenancy import scoped_query
from app.core.logging import logger
from app.services.report_generator import generate_investigation_report, generate_executive_summary

router = APIRouter()


def _alert_id_to_filename(alert_id: str, prefix: str) -> str:
    """Generates a clean, safe PDF filename from an alert ID."""
    safe_id = alert_id[:12].replace("/", "_").replace("\\", "_")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
    return f"forensiq_{prefix}_{safe_id}_{ts}.pdf"


async def _fetch_alert_for_report(
    alert_id: str,
    db: AsyncIOMotorDatabase,
    user: dict,
) -> dict:
    """Fetches and validates an alert document for PDF generation."""
    alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    # Normalize _id for serialization
    alert["_id"] = str(alert["_id"])
    return alert


@router.get(
    "/{alert_id:path}/report/full",
    summary="Download Full Investigation PDF Report",
    description=(
        "Generates and downloads a complete multi-page PDF investigation report for the given alert, "
        "including risk assessment, AI recommendations, MITRE mappings, timeline, IOC enrichment, "
        "correlated events, and raw telemetry context."
    ),
    tags=["reports"],
)
async def download_full_report(
    alert_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Generates and streams a full investigation PDF report."""
    alert = await _fetch_alert_for_report(alert_id, db, user)
    logger.info("report_generation_started", alert_id=alert_id, report_type="full", user=user.get("id"))

    try:
        pdf_bytes = generate_investigation_report(alert)
    except Exception as exc:
        logger.error("report_generation_failed", alert_id=alert_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(exc)}")

    filename = _alert_id_to_filename(alert_id, "investigation_report")
    logger.info("report_generation_success", alert_id=alert_id, report_type="full", bytes=len(pdf_bytes))

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "X-Forensiq-Report-Type": "full",
            "X-Forensiq-Alert-ID": alert_id,
        },
    )


@router.get(
    "/{alert_id:path}/report/executive",
    summary="Download Executive Summary PDF",
    description=(
        "Generates and downloads a concise one-page executive summary PDF for the given alert, "
        "suitable for leadership review, compliance audits, and incident handoff documentation."
    ),
    tags=["reports"],
)
async def download_executive_summary(
    alert_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Generates and streams a one-page executive summary PDF."""
    alert = await _fetch_alert_for_report(alert_id, db, user)
    logger.info("report_generation_started", alert_id=alert_id, report_type="executive", user=user.get("id"))

    try:
        pdf_bytes = generate_executive_summary(alert)
    except Exception as exc:
        logger.error("report_generation_failed", alert_id=alert_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Executive summary generation failed: {str(exc)}")

    filename = _alert_id_to_filename(alert_id, "executive_summary")
    logger.info("report_generation_success", alert_id=alert_id, report_type="executive", bytes=len(pdf_bytes))

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "X-Forensiq-Report-Type": "executive",
            "X-Forensiq-Alert-ID": alert_id,
        },
    )
