# Chapter 7: Server-Side PDF Reporting Engine

Security investigations are incomplete until findings can be shared with leadership, legal teams, and regulatory bodies. 

This chapter explains how Forensiq's **Server-Side PDF Reporting Engine** generates publication-ready, branded binary PDF reports directly from Python using **ReportLab**.

---

## 1. Why Server-Side Binary PDF? (Client Print vs Server PDF)

Many web applications implement "PDF export" by calling `window.print()` in JavaScript. This approach has critical flaws:
- Page breaks cut directly through text lines, graphs, or tables.
- Browser margins, headers, and footers ("Page 1 of 2", URL strings, dates) clutter the document.
- Visual appearance varies depending on whether the analyst uses Chrome, Firefox, Safari, or Edge.

### The Forensiq Approach:
Forensiq generates pure binary PDF documents on the server using **ReportLab** ([`backend/app/services/report_generator.py`](file:///d:/Forensiq/backend/app/services/report_generator.py)).
- Strict typography, custom corporate headers, page numbering, and clean margins.
- Proper pagination with defensive table wrapping so data never clips.
- Served directly via HTTP with `Content-Type: application/pdf` and `Content-Disposition: attachment`.

---

## 2. The Two Report Formats

Forensiq supports two distinct report types designed for different audiences:

### Format 1: Executive Summary Report (`report_type=executive`)
- **Target Audience**: Chief Information Security Officer (CISO), Chief Technology Officer (CTO), Board of Directors, or Legal Counsel.
- **Length**: Exactly **1 Page**.
- **What it Contains**:
  1. **Branded Header**: Forensiq SOC logo, Confidentiality marking, Date, and Case ID.
  2. **High-Level Incident Overview**: Hostname, affected user, base severity, and incident title.
  3. **Scorecard Grid**: Risk Score (e.g. `85/100`), Threat Priority (`P1 - Critical`), AI Confidence (`94%`), and Status.
  4. **Executive Verdict & Summary**: 2-3 paragraph plain-English summary of what happened without confusing raw log syntax.
  5. **Immediate Strategic Recommendations**: High-level action items (e.g., *"Isolate server immediately, force domain-wide credential reset, block external IP on Palo Alto firewalls"*).

---

### Format 2: Full Technical Investigation Report (`report_type=full`)
- **Target Audience**: Tier 2/3 SOC Analysts, Digital Forensics & Incident Response (DFIR) specialists, and External Forensic Auditors.
- **Length**: **Multi-page** comprehensive dossier.
- **What it Contains**:
  1. **Executive Summary & Threat Metrics**: Complete scorecards and verdict.
  2. **Adversary Tactic & Technique Classification**: Official MITRE ATT&CK IDs, tactic categories, and attack definitions.
  3. **Extracted Indicators of Compromise (IOCs)**: Table of IPs, domains, and file hashes with their respective threat scores and VirusTotal / AbuseIPDB reputation flags.
  4. **Attack Chronology (Timeline)**: Complete chronological sequence of events from root process spawn to final artifact creation.
  5. **Correlated Security Incidents**: Table of any other alerts across the enterprise sharing the same host, user, or IP in the last 24 hours.
  6. **Process & Forensic Telemetry**: Parent PID, Target PID, full unfiltered command lines, and registry modifications.
  7. **Full Step-by-Step Remediation Playbook**: Detailed containment, eradication, and post-incident hardening checklist.

---

## 3. How the PDF API Works

### Backend Endpoint:
```http
GET /api/v1/alerts/{alert_id}/report/pdf?report_type={executive|full}
Authorization: Bearer <jwt_access_token>
```

### Python Implementation (`backend/app/api/v1/endpoints/reports.py`):
```python
@router.get("/alerts/{alert_id}/report/pdf")
async def download_alert_pdf_report(
    alert_id: str,
    report_type: str = Query("full", regex="^(full|executive)$"),
    current_user: dict = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    # 1. Fetch alert from MongoDB
    alert = await db.alerts.find_one({"_id": ObjectId(alert_id), "tenant_id": current_user["tenant_id"]})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # 2. Compile binary PDF in memory via ReportLab
    pdf_bytes = generate_pdf_report_binary(alert, report_type=report_type)
    
    # 3. Stream binary response with forced attachment download
    filename = f"forensiq_{report_type}_report_{alert_id[:8]}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
```

### Frontend 1-Click Trigger:
In both `investigations/page.tsx` and `reports/page.tsx`, clicking the **Exec PDF** or **Full Report PDF** button initiates an authenticated `fetch()`, receives the binary blob, creates a temporary browser object URL, triggers the instant file download, and cleans up memory automatically.

---

*Next Chapter: [Chapter 8: Concrete Real-World Walkthrough Example](file:///d:/Forensiq/docs/project_handbook/08_concrete_case_walkthrough_example.md)*
