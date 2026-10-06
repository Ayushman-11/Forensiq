"""
PDF Report Generator Service for Forensiq.
Generates full investigation reports and one-page executive summaries using ReportLab.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus import SimpleDocTemplate

# ─── Color Palette ───────────────────────────────────────────────────────────
DARK_BG = colors.HexColor("#0C1322")
NAVY = colors.HexColor("#0E1A2E")
CARD_BG = colors.HexColor("#111C2E")
BORDER = colors.HexColor("#1E2E48")
CYAN = colors.HexColor("#22D3EE")
CYAN_DIM = colors.HexColor("#0E7490")
AMBER = colors.HexColor("#F59E0B")
ROSE = colors.HexColor("#F43F5E")
EMERALD = colors.HexColor("#10B981")
SLATE_300 = colors.HexColor("#CBD5E1")
SLATE_400 = colors.HexColor("#94A3B8")
SLATE_200 = colors.HexColor("#E2E8F0")
WHITE = colors.white


SEVERITY_COLORS = {
    "critical": colors.HexColor("#F43F5E"),
    "high": colors.HexColor("#F97316"),
    "medium": colors.HexColor("#38BDF8"),
    "low": colors.HexColor("#34D399"),
}

STATUS_COLORS = {
    "investigated": EMERALD,
    "new": AMBER,
    "investigating": CYAN,
    "closed": SLATE_400,
    "escalated": ROSE,
    "suppressed": SLATE_400,
}


# ─── Style helpers ────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=26,
            textColor=WHITE,
            leading=32,
            alignment=TA_LEFT,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontName="Helvetica",
            fontSize=11,
            textColor=SLATE_400,
            leading=16,
            alignment=TA_LEFT,
        ),
        "section_heading": ParagraphStyle(
            "section_heading",
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=CYAN,
            leading=16,
            spaceBefore=14,
            spaceAfter=6,
            borderPadding=(0, 0, 3, 0),
        ),
        "label": ParagraphStyle(
            "label",
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=SLATE_400,
            leading=10,
            spaceAfter=1,
        ),
        "value": ParagraphStyle(
            "value",
            fontName="Helvetica",
            fontSize=9,
            textColor=SLATE_200,
            leading=13,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=9,
            textColor=SLATE_300,
            leading=14,
            spaceAfter=8,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=8,
            textColor=SLATE_300,
            leading=11,
            spaceAfter=4,
            backColor=CARD_BG,
        ),
        "badge_critical": ParagraphStyle(
            "badge_critical",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=ROSE,
            leading=14,
            alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName="Helvetica",
            fontSize=7,
            textColor=SLATE_400,
            alignment=TA_CENTER,
        ),
        "exec_kpi_value": ParagraphStyle(
            "exec_kpi_value",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=WHITE,
            leading=26,
            alignment=TA_CENTER,
        ),
        "exec_kpi_label": ParagraphStyle(
            "exec_kpi_label",
            fontName="Helvetica",
            fontSize=8,
            textColor=SLATE_400,
            leading=11,
            alignment=TA_CENTER,
        ),
        "exec_title": ParagraphStyle(
            "exec_title",
            fontName="Helvetica-Bold",
            fontSize=20,
            textColor=WHITE,
            leading=26,
            alignment=TA_LEFT,
        ),
        "recommendation": ParagraphStyle(
            "recommendation",
            fontName="Helvetica",
            fontSize=9,
            textColor=SLATE_200,
            leading=14,
            spaceAfter=6,
            leftIndent=10,
        ),
    }


def _page_background(canvas, doc):
    """Draw dark-themed background on every page."""
    canvas.saveState()
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, doc.width + doc.leftMargin + doc.rightMargin,
                doc.height + doc.topMargin + doc.bottomMargin, fill=True, stroke=False)
    # Header bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, doc.height + doc.topMargin - 18 * mm,
                doc.width + doc.leftMargin + doc.rightMargin, 18 * mm,
                fill=True, stroke=False)
    # Header text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(CYAN)
    canvas.drawString(doc.leftMargin, doc.height + doc.topMargin - 12 * mm, "FORENSIQ  ·  SECURITY OPERATIONS PLATFORM")
    canvas.setFillColor(SLATE_400)
    canvas.setFont("Helvetica", 7)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    canvas.drawRightString(doc.width + doc.leftMargin, doc.height + doc.topMargin - 12 * mm, f"GENERATED: {ts}")
    # Footer
    canvas.setFillColor(BORDER)
    canvas.rect(0, 0, doc.width + doc.leftMargin + doc.rightMargin, 14 * mm, fill=True, stroke=False)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE_400)
    canvas.drawCentredString(
        (doc.width + doc.leftMargin + doc.rightMargin) / 2,
        5 * mm,
        f"FORENSIQ CONFIDENTIAL — FOR AUTHORIZED SECURITY PERSONNEL ONLY  |  Page {doc.page}",
    )
    canvas.restoreState()


def _hr(color=BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=4)


def _plain_text(value: Any, fallback: str = "—") -> str:
    """Escape alert data before placing it in ReportLab paragraph markup."""
    return escape(str(value)) if value not in (None, "") else fallback


def _kv_table(pairs: list[tuple[str, str]], styles_dict: dict) -> Table:
    """Renders a two-column key-value table."""
    data = []
    for label, value in pairs:
        data.append([
            Paragraph(_plain_text(label).upper(), styles_dict["label"]),
            Paragraph(_plain_text(value), styles_dict["value"]),
        ])
    t = Table(data, colWidths=["30%", "70%"])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [DARK_BG, CARD_BG]),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("ROUNDEDCORNERS", [4]),
    ]))
    return t


def _severity_badge(severity: str) -> str:
    color_map = {
        "critical": "#F43F5E",
        "high": "#F97316",
        "medium": "#38BDF8",
        "low": "#34D399",
    }
    col = color_map.get(severity.lower(), "#94A3B8")
    return f'<font color="{col}"><b>{severity.upper()}</b></font>'


# ─── Full Investigation Report ────────────────────────────────────────────────

def generate_investigation_report(alert: dict[str, Any]) -> bytes:
    """
    Generates a full multi-page PDF investigation report for a given alert document.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=3 * cm,
        bottomMargin=2.5 * cm,
        title=f"Forensiq Investigation Report — {alert.get('title', 'Unknown')}",
        author="Forensiq Security Operations Platform",
    )

    S = _styles()
    story = []

    # ── Cover Block ──────────────────────────────────────────────────────────
    severity = alert.get("severity", "unknown").lower()
    sev_color = SEVERITY_COLORS.get(severity, SLATE_400)
    status = alert.get("status", "Unknown")
    status_color = STATUS_COLORS.get(status.lower(), SLATE_400)

    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph("FORENSIQ INVESTIGATION REPORT", ParagraphStyle(
        "cover_label", fontName="Helvetica-Bold", fontSize=9, textColor=CYAN, leading=12, spaceAfter=8)))

    title_text = _plain_text(alert.get("title"), "Untitled Alert")
    story.append(Paragraph(title_text, S["cover_title"]))
    story.append(Spacer(1, 0.3 * cm))

    # Severity + Status bar
    meta_data = [
        [
            Paragraph(f'Severity: <font color="#{sev_color.hexval()[2:]}">{severity.upper()}</font>', ParagraphStyle(
                "sv", fontName="Helvetica-Bold", fontSize=10, textColor=WHITE, leading=14)),
                Paragraph(f'Status: <font color="#{status_color.hexval()[2:]}">{_plain_text(status)}</font>', ParagraphStyle(
                "st", fontName="Helvetica-Bold", fontSize=10, textColor=WHITE, leading=14)),
                Paragraph(f'Alert ID: <font color="#22D3EE">{_plain_text(alert.get("_id"), "N/A")}</font>', ParagraphStyle(
                "aid", fontName="Helvetica", fontSize=8, textColor=SLATE_400, leading=12)),
        ]
    ]
    meta_tbl = Table(meta_data, colWidths=["28%", "28%", "44%"])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.3 * cm))

    # Generated date
    gen_ts = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
    created = alert.get("created_at")
    if isinstance(created, datetime):
        created_str = created.strftime("%Y-%m-%d %H:%M UTC")
    elif isinstance(created, str):
        created_str = created[:19].replace("T", " ") + " UTC"
    else:
        created_str = "Unknown"

    story.append(_kv_table([
        ("Report Generated", gen_ts),
        ("Alert Created", created_str),
        ("Target Host", alert.get("host", "Unknown")),
        ("Affected Account", alert.get("user", "Unknown")),
        ("Detection Rule", alert.get("rule_name", "Unknown")),
        ("Source SIEM", alert.get("source_siem", "Forensiq Internal")),
    ], S))
    story.append(Spacer(1, 0.5 * cm))

    # ── Section 1: Risk Assessment ────────────────────────────────────────────
    story.append(Paragraph("1. RISK ASSESSMENT", S["section_heading"]))
    story.append(_hr(CYAN_DIM))

    risk_assessment = alert.get("risk_assessment") or {}
    ai_confidence = alert.get("ai_confidence", risk_assessment.get("confidence_score", 0))
    risk_score = alert.get("risk_score", risk_assessment.get("risk_score", 0))
    priority = alert.get("priority", risk_assessment.get("priority", "Unknown"))

    # KPI Row
    kpi_data = [[
        _kpi_cell(str(risk_score) + "/100", "Risk Score", S),
        _kpi_cell(str(ai_confidence) + "%", "AI Confidence", S),
        _kpi_cell(priority.upper() if priority else "—", "Priority Level", S),
        _kpi_cell(str(len(alert.get("mitre_mappings") or [])) + " TTPs", "MITRE Mappings", S),
    ]]
    kpi_tbl = Table(kpi_data, colWidths=["25%", "25%", "25%", "25%"])
    kpi_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
    ]))
    story.append(kpi_tbl)
    story.append(Spacer(1, 0.4 * cm))

    if risk_assessment.get("summary"):
        story.append(Paragraph("Risk Summary", S["label"]))
        story.append(Paragraph(_plain_text(risk_assessment["summary"]), S["body"]))

    # ── Section 2: AI Recommendation ─────────────────────────────────────────
    story.append(Paragraph("2. AI AGENT RECOMMENDATION", S["section_heading"]))
    story.append(_hr(CYAN_DIM))
    recommendation = alert.get("recommendation")
    if recommendation:
        rec_text = recommendation.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        story.append(Paragraph(rec_text, S["recommendation"]))
    else:
        story.append(Paragraph("No automated investigation has been performed for this alert.", S["body"]))
    story.append(Spacer(1, 0.3 * cm))

    # ── Section 3: MITRE ATT&CK ───────────────────────────────────────────────
    mitre_mappings = alert.get("mitre_mappings") or []
    if not mitre_mappings and alert.get("mitre_technique"):
        mitre_mappings = [{"technique": alert.get("mitre_technique"), "tactic": alert.get("mitre_tactic"), "name": ""}]

    if mitre_mappings:
        story.append(Paragraph("3. MITRE ATT&CK MAPPINGS", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        headers = [
            Paragraph("TACTIC", S["label"]),
            Paragraph("TECHNIQUE", S["label"]),
            Paragraph("NAME", S["label"]),
        ]
        rows = [headers]
        for m in mitre_mappings:
            rows.append([
                Paragraph(_plain_text(m.get("tactic")), S["value"]),
                Paragraph(_plain_text(m.get("technique")), S["value"]),
                Paragraph(_plain_text(m.get("name")), S["value"]),
            ])
        t = Table(rows, colWidths=["28%", "22%", "50%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_BG, CARD_BG]),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4 * cm))

    # ── Section 4: Attack Timeline ────────────────────────────────────────────
    timeline = alert.get("timeline") or []
    if timeline:
        story.append(Paragraph("4. ATTACK PROGRESSION TIMELINE", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        for i, evt in enumerate(timeline, 1):
            ts = evt.get("timestamp") or "—"
            desc = _plain_text(evt.get("description"))
            src = _plain_text(evt.get("source"))
            story.append(Paragraph(
                f'<font color="#22D3EE">▶ Step {i}</font>  '
                f'<font color="#CBD5E1">{desc}</font>',
                S["value"],
            ))
            story.append(Paragraph(f'Timestamp: {_plain_text(ts)}  ·  Source: {src}', S["label"]))
        story.append(Spacer(1, 0.4 * cm))

    # ── Section 5: IOC Enrichment ─────────────────────────────────────────────
    enrichments = alert.get("enrichments") or []
    extracted_iocs = alert.get("extracted_iocs") or []

    if enrichments:
        story.append(Paragraph("5. THREAT INTELLIGENCE & IOC ENRICHMENT", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        headers = [
            Paragraph("IOC", S["label"]),
            Paragraph("TYPE", S["label"]),
            Paragraph("REPUTATION", S["label"]),
            Paragraph("THREAT SCORE", S["label"]),
            Paragraph("SOURCE", S["label"]),
        ]
        rows = [headers]
        for e in enrichments:
            rep = e.get("reputation", "Unknown")
            rep_color = {"malicious": "#F43F5E", "suspicious": "#F97316", "clean": "#34D399"}.get(
                rep.lower() if rep else "", "#94A3B8"
            )
            rows.append([
                Paragraph(_plain_text(e.get("ioc")), S["mono"]),
                Paragraph(_plain_text(e.get("ioc_type")), S["value"]),
                Paragraph(f'<font color="{rep_color}">{_plain_text(rep)}</font>', S["value"]),
                Paragraph(_plain_text(e.get("threat_score")), S["value"]),
                Paragraph(_plain_text(e.get("source")), S["value"]),
            ])
        t = Table(rows, colWidths=["30%", "12%", "14%", "14%", "30%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_BG, CARD_BG]),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4 * cm))
    elif extracted_iocs:
        story.append(Paragraph("5. EXTRACTED INDICATORS OF COMPROMISE", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        for ioc in extracted_iocs:
            story.append(Paragraph(f"• {_plain_text(ioc)}", S["mono"]))
        story.append(Spacer(1, 0.3 * cm))

    # ── Section 6: Correlated Events ──────────────────────────────────────────
    correlations = alert.get("correlations") or []
    if correlations:
        story.append(Paragraph("6. CORRELATED EVENTS", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        headers = [
            Paragraph("ALERT ID", S["label"]),
            Paragraph("TITLE", S["label"]),
            Paragraph("SEVERITY", S["label"]),
            Paragraph("STATUS", S["label"]),
        ]
        rows = [headers]
        for c in correlations[:15]:  # cap at 15
            c_sev = c.get("severity", "unknown")
            sev_col = {"critical": "#F43F5E", "high": "#F97316", "medium": "#38BDF8", "low": "#34D399"}.get(
                c_sev.lower() if c_sev else "", "#94A3B8")
            c_title = _plain_text(c.get("title"))
            rows.append([
                Paragraph(_plain_text(c.get("alert_id"))[:20], S["mono"]),
                Paragraph(c_title[:80], S["value"]),
                Paragraph(f'<font color="{sev_col}">{c_sev.upper() if c_sev else "—"}</font>', S["value"]),
                Paragraph(_plain_text(c.get("status")), S["value"]),
            ])
        t = Table(rows, colWidths=["20%", "50%", "15%", "15%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_BG, CARD_BG]),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4 * cm))

    # ── Section 7: Raw Context / Telemetry Fields ─────────────────────────────
    context = alert.get("context") or {}
    raw_alert = alert.get("raw_alert_data") or alert.get("raw_event") or {}
    telemetry = {**raw_alert, **context}

    if telemetry:
        story.append(Paragraph("7. RAW TELEMETRY CONTEXT", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        pairs = []
        for k, v in list(telemetry.items())[:20]:
            pairs.append((str(k).replace("_", " ").title(), str(v)[:120]))
        story.append(_kv_table(pairs, S))
        story.append(Spacer(1, 0.4 * cm))

    # ── Section 8: Evidence Summary ───────────────────────────────────────────
    evidence = alert.get("evidence") or {}
    if evidence:
        story.append(Paragraph("8. EVIDENCE SUMMARY", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        ev_pairs = [(k.replace("_", " ").title(), str(v)) for k, v in evidence.items()]
        story.append(_kv_table(ev_pairs, S))

    # ── Closing Disclaimer ────────────────────────────────────────────────────
    story.append(Spacer(1, 1 * cm))
    story.append(_hr())
    story.append(Paragraph(
        "This report was automatically generated by the Forensiq AI Security Operations Platform. "
        "The findings and recommendations herein are based on automated AI analysis and should be "
        "reviewed by qualified security personnel. Classification: CONFIDENTIAL.",
        S["footer"],
    ))

    doc.build(story, onFirstPage=_page_background, onLaterPages=_page_background)
    return buf.getvalue()


def _kpi_cell(value: str, label: str, S: dict) -> list:
    return [Paragraph(value, S["exec_kpi_value"]), Paragraph(label, S["exec_kpi_label"])]


# ─── Executive Summary (1-page) ───────────────────────────────────────────────

def generate_executive_summary(alert: dict[str, Any]) -> bytes:
    """
    Generates a concise one-page executive summary PDF.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2.2 * cm,
        rightMargin=2.2 * cm,
        topMargin=2.8 * cm,
        bottomMargin=2.2 * cm,
        title=f"Executive Summary — {alert.get('title', 'Security Incident')}",
        author="Forensiq Security Operations Platform",
    )

    S = _styles()
    story = []

    severity = alert.get("severity", "unknown").lower()
    sev_color = SEVERITY_COLORS.get(severity, SLATE_400)
    status = alert.get("status", "Unknown")
    risk_score = alert.get("risk_score") or (alert.get("risk_assessment") or {}).get("risk_score", 0)
    ai_confidence = alert.get("ai_confidence") or (alert.get("risk_assessment") or {}).get("confidence_score", 0)
    priority = (alert.get("priority") or (alert.get("risk_assessment") or {}).get("priority") or "Unknown").upper()

    # Title block
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("EXECUTIVE SECURITY SUMMARY", ParagraphStyle(
        "exec_sub_label", fontName="Helvetica-Bold", fontSize=8,
        textColor=CYAN, leading=12, spaceAfter=6)))

    title_text = _plain_text(alert.get("title"), "Untitled Security Incident")
    story.append(Paragraph(title_text, S["exec_title"]))
    story.append(Spacer(1, 0.2 * cm))

    # Severity + Status quick read
    created = alert.get("created_at", "")
    if isinstance(created, datetime):
        created_str = created.strftime("%Y-%m-%d %H:%M UTC")
    elif isinstance(created, str):
        created_str = created[:19].replace("T", " ") + " UTC"
    else:
        created_str = "Unknown"

    sev_hex = sev_color.hexval()[2:]
    meta_row = [[
        Paragraph(
            f'<font color="#{sev_hex}">●</font>  Severity: <font color="#{sev_hex}"><b>{severity.upper()}</b></font>',
            ParagraphStyle("meta", fontName="Helvetica", fontSize=10, textColor=WHITE, leading=14)),
        Paragraph(f'Status: <b>{_plain_text(status)}</b>', ParagraphStyle("meta2", fontName="Helvetica", fontSize=10, textColor=SLATE_300, leading=14)),
        Paragraph(f'Detected: {_plain_text(created_str)}', ParagraphStyle("meta3", fontName="Helvetica", fontSize=9, textColor=SLATE_400, leading=14)),
    ]]
    meta_tbl = Table(meta_row, colWidths=["33%", "33%", "34%"])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.4 * cm))

    # KPI metrics row
    evidence = alert.get("evidence") or {}
    ioc_count = evidence.get("ioc_count", len(alert.get("extracted_iocs") or []))
    corr_count = evidence.get("correlated_alert_count", len(alert.get("correlations") or []))
    mitre_count = evidence.get("mitre_count", len(alert.get("mitre_mappings") or []))

    kpi_data = [[
        [Paragraph(f"{risk_score}/100", S["exec_kpi_value"]), Paragraph("Risk Score", S["exec_kpi_label"])],
        [Paragraph(f"{ai_confidence}%", S["exec_kpi_value"]), Paragraph("AI Confidence", S["exec_kpi_label"])],
        [Paragraph(priority, S["exec_kpi_value"]), Paragraph("Priority", S["exec_kpi_label"])],
        [Paragraph(str(ioc_count), S["exec_kpi_value"]), Paragraph("IOCs Found", S["exec_kpi_label"])],
        [Paragraph(str(corr_count), S["exec_kpi_value"]), Paragraph("Related Events", S["exec_kpi_label"])],
        [Paragraph(str(mitre_count), S["exec_kpi_value"]), Paragraph("MITRE TTPs", S["exec_kpi_label"])],
    ]]
    kpi_tbl = Table(kpi_data, colWidths=["16.7%"] * 6)
    kpi_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
    ]))
    story.append(kpi_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # Incident Details
    story.append(Paragraph("INCIDENT DETAILS", S["section_heading"]))
    story.append(_hr(CYAN_DIM))
    story.append(_kv_table([
        ("Target Host", alert.get("host") or "Unknown"),
        ("Affected Account", alert.get("user") or "Unknown"),
        ("Detection Rule", alert.get("rule_name") or "Unknown"),
        ("Source Network IP", alert.get("source_ip") or "N/A"),
        ("Destination IP", alert.get("dest_ip") or "N/A"),
        ("Process", alert.get("process_name") or "N/A"),
        ("Alert ID", alert.get("_id") or "N/A"),
    ], S))
    story.append(Spacer(1, 0.4 * cm))

    # AI Recommendation
    story.append(Paragraph("AI RECOMMENDATION & RESPONSE ACTIONS", S["section_heading"]))
    story.append(_hr(CYAN_DIM))
    recommendation = alert.get("recommendation") or "No automated investigation performed. Manual triage required."
    rec_text = _plain_text(recommendation)
    story.append(Paragraph(rec_text, S["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # MITRE Highlights (condensed)
    mitre_mappings = alert.get("mitre_mappings") or []
    if not mitre_mappings and alert.get("mitre_technique"):
        mitre_mappings = [{"technique": alert.get("mitre_technique"), "tactic": alert.get("mitre_tactic"), "name": ""}]
    if mitre_mappings:
        story.append(Paragraph("MITRE ATT&CK TECHNIQUES IDENTIFIED", S["section_heading"]))
        story.append(_hr(CYAN_DIM))
        mitre_text = "  ·  ".join(
            [f'{_plain_text(m.get("technique"), "")} ({_plain_text(m.get("tactic"), "")})' for m in mitre_mappings[:5]]
        )
        story.append(Paragraph(mitre_text, S["body"]))
        story.append(Spacer(1, 0.3 * cm))

    # Closure disclaimer
    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr())
    story.append(Paragraph(
        f"Prepared by Forensiq AI · {datetime.now(timezone.utc).strftime('%B %d, %Y')} · "
        "CONFIDENTIAL — For Leadership & Compliance Review Only. "
        "This summary was auto-generated and should be reviewed by security leadership before distribution.",
        S["footer"],
    ))

    doc.build(story, onFirstPage=_page_background, onLaterPages=_page_background)
    return buf.getvalue()
