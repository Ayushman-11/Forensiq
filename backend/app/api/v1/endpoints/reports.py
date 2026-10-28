"""
Report Generation Endpoints.
Provides PDF download endpoints for full investigation reports, executive summaries,
and consolidated SOC operations reports.
"""

from datetime import datetime, timezone
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.api.deps import get_current_user
from app.core.tenancy import scoped_query, tenant_id
from app.core.logging import logger
from app.core.errors import internal_error
from app.services.report_generator import generate_investigation_report, generate_executive_summary

router = APIRouter()


def _alert_id_to_filename(alert_id: str, prefix: str) -> str:
    """Generates a clean, safe PDF filename from an alert ID."""
    safe_id = alert_id[:16].replace("/", "_").replace("\\", "_").replace(":", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
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
    alert["_id"] = str(alert["_id"])
    return alert


@router.get(
    "/{alert_id:path}/report/pdf",
    summary="Download Investigation PDF Report",
    description=(
        "Streams a publication-ready PDF binary for an alert. "
        "Supports 'full' investigation report (multi-page) or 'executive' summary (1-page)."
    ),
    tags=["reports"],
)
async def download_report_pdf(
    alert_id: str,
    report_type: Literal["full", "executive"] = Query(
        "full", description="Type of PDF report to generate: 'full' or 'executive'"
    ),
    inline: bool = Query(
        False, description="Serve inline for in-browser PDF viewing instead of file download"
    ),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Generates and streams publication-ready investigation PDF binary."""
    alert = await _fetch_alert_for_report(alert_id, db, user)
    logger.info("report_generation_started", alert_id=alert_id, report_type=report_type, user=user.get("email"))

    try:
        if report_type == "executive":
            pdf_bytes = generate_executive_summary(alert)
            prefix = "executive_summary"
        else:
            pdf_bytes = generate_investigation_report(alert)
            prefix = "investigation_report"
    except Exception as exc:
        raise internal_error("report_generation_failed", exc, alert_id=alert_id)

    filename = _alert_id_to_filename(alert_id, prefix)
    disposition = "inline" if inline else "attachment"
    logger.info("report_generation_success", alert_id=alert_id, report_type=report_type, bytes=len(pdf_bytes))

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "X-Forensiq-Report-Type": report_type,
            "X-Forensiq-Alert-ID": alert_id,
        },
    )


@router.get(
    "/{alert_id:path}/report/full",
    summary="Download Full Investigation PDF Report",
    description="Shortcut for /report/pdf?report_type=full",
    tags=["reports"],
)
async def download_full_report(
    alert_id: str,
    inline: bool = Query(False),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Generates and streams a full multi-page investigation PDF report."""
    return await download_report_pdf(alert_id, report_type="full", inline=inline, db=db, user=user)


@router.get(
    "/{alert_id:path}/report/executive",
    summary="Download Executive Summary PDF",
    description="Shortcut for /report/pdf?report_type=executive",
    tags=["reports"],
)
async def download_executive_summary(
    alert_id: str,
    inline: bool = Query(False),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Generates and streams a one-page executive summary PDF."""
    return await download_report_pdf(alert_id, report_type="executive", inline=inline, db=db, user=user)
