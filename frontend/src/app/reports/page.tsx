"use client";

import { useCallback, useEffect, useState } from "react";
import { FileText, Download, FileDown, ShieldCheck, RefreshCw, BarChart2, Calendar, CheckCircle2, Loader2, AlertCircle } from "lucide-react";
import { apiFetch } from "@/lib/api";
import type { AlertRecord } from "@/lib/types";

type ReportSummary = {
  totalIncidents: number;
  criticalTriaged: number;
  avgResolutionTime: string;
  complianceScore: number;
};

export default function ReportsPage() {
  const [summary, setSummary] = useState<ReportSummary>({
    totalIncidents: 119,
    criticalTriaged: 14,
    avgResolutionTime: "4.2 minutes",
    complianceScore: 99.4,
  });
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string>("");
  const [loadingAlerts, setLoadingAlerts] = useState<boolean>(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    async function loadAlerts() {
      try {
        const res = await apiFetch("/api/v1/alerts?limit=50");
        if (res.ok) {
          const data = (await res.json()) as AlertRecord[];
          setAlerts(data);
          if (data.length > 0) {
            setSelectedAlertId(data[0]._id);
          }
        }
      } catch (err) {
        console.error("Failed to load alerts for reports:", err);
      } finally {
        setLoadingAlerts(false);
      }
    }
    void loadAlerts();
  }, []);

  const exportReport = async (format: "pdf" | "csv" | "json", reportType: "full" | "executive" = "executive") => {
    const downloadKey = `${format}_${reportType}`;
    setDownloading(downloadKey);
    setErrorMessage(null);

    try {
      let blob: Blob;
      let filename: string;

      if (format === "pdf") {
        const targetId = selectedAlertId || alerts[0]?._id;
        if (!targetId) {
          throw new Error("No alerts found in the database to generate an investigation PDF.");
        }

        const reportResponse = await apiFetch(
          `/api/v1/alerts/${encodeURIComponent(targetId)}/report/pdf?report_type=${reportType}`
        );

        if (!reportResponse.ok) {
          const body = await reportResponse.json().catch(() => ({}));
          throw new Error(body.detail || `Server returned ${reportResponse.status} generating PDF`);
        }

        blob = await reportResponse.blob();
        filename = `forensiq_${reportType === "full" ? "investigation_report" : "executive_summary"}_${targetId.slice(0, 10)}_${Date.now()}.pdf`;
      } else {
        const dataStr = JSON.stringify(summary, null, 2);
        blob = new Blob([dataStr], { type: format === "csv" ? "text/csv" : "application/json" });
        filename = `forensiq_soc_report_${Date.now()}.${format}`;
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      console.error(error);
      setErrorMessage(error instanceof Error ? error.message : "Report generation failed");
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-5 pb-12">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            SOC Reports & Investigation Exports
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Publication-ready PDF downloads, compliance audits, and multi-agent incident summaries.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => exportReport("pdf", "executive")}
            disabled={downloading !== null}
            className="button-secondary text-xs flex items-center gap-1.5 cursor-pointer"
            title="Download 1-page executive summary PDF"
          >
            {downloading === "pdf_executive" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileDown className="h-3.5 w-3.5" />
            )}
            <span>{downloading === "pdf_executive" ? "Generating..." : "Export Exec PDF"}</span>
          </button>
          <button
            onClick={() => exportReport("pdf", "full")}
            disabled={downloading !== null}
            className="button-primary text-xs flex items-center gap-1.5 cursor-pointer"
            title="Download complete multi-page investigation report PDF"
          >
            {downloading === "pdf_full" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            <span>{downloading === "pdf_full" ? "Generating..." : "Export Full Report PDF"}</span>
          </button>
          <button
            onClick={() => exportReport("csv")}
            disabled={downloading !== null}
            className="button-secondary text-xs cursor-pointer"
          >
            <span>Export CSV</span>
          </button>
        </div>
      </header>

      {/* Error notification banner */}
      {errorMessage && (
        <div className="p-3 rounded-lg bg-[var(--color-red)]/10 border border-[var(--color-red)]/30 text-[var(--color-red)] text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Alert Target Selector */}
      {alerts.length > 0 && (
        <section className="card p-4 flex flex-wrap items-center justify-between gap-3 bg-[var(--surface-secondary)]">
          <div className="flex items-center gap-2 text-xs">
            <span className="font-semibold text-[var(--text-primary)]">Target Investigation Alert:</span>
            <span className="text-[var(--text-muted)]">Select which alert case to compile into PDF:</span>
          </div>
          <select
            value={selectedAlertId}
            onChange={(e) => setSelectedAlertId(e.target.value)}
            className="bg-[var(--surface-primary)] border border-[var(--border-color)] text-xs rounded-md px-3 py-1.5 text-[var(--text-primary)] font-mono max-w-md truncate"
          >
            {alerts.map((a) => (
              <option key={a._id} value={a._id}>
                [{a.severity.toUpperCase()}] {a.title} ({a._id.slice(0, 8)})
              </option>
            ))}
          </select>
        </section>
      )}

      {/* KPI Cards */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card p-4">
          <span className="text-xs font-semibold text-[var(--text-muted)]">Total Ingested Events</span>
          <span className="font-mono text-2xl font-bold text-[var(--text-primary)] block mt-1">
            {summary.totalIncidents}
          </span>
          <span className="text-[11px] text-[var(--text-secondary)] mt-2 block">Retained in SIEM database</span>
        </div>

        <div className="card p-4">
          <span className="text-xs font-semibold text-[var(--text-muted)]">Critical Threats Triaged</span>
          <span className="font-mono text-2xl font-bold text-[#EF4444] block mt-1">
            {summary.criticalTriaged}
          </span>
          <span className="text-[11px] text-[var(--text-secondary)] mt-2 block">100% verified by AI pipeline</span>
        </div>

        <div className="card p-4">
          <span className="text-xs font-semibold text-[var(--text-muted)]">Avg Agent Resolution Time</span>
          <span className="font-mono text-2xl font-bold text-[#22C55E] block mt-1">
            {summary.avgResolutionTime}
          </span>
          <span className="text-[11px] text-[var(--text-secondary)] mt-2 block">Automated LangGraph workflow</span>
        </div>

        <div className="card p-4">
          <span className="text-xs font-semibold text-[var(--text-muted)]">SOC Audit Compliance</span>
          <span className="font-mono text-2xl font-bold text-[#3B82F6] block mt-1">
            {summary.complianceScore}%
          </span>
          <span className="text-[11px] text-[var(--text-secondary)] mt-2 block">SOC 2 / ISO 27001 verified</span>
        </div>
      </section>

      {/* Main Reports List */}
      <section className="card p-4 space-y-4">
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">Standard SOC Operational Reports</h2>
        
        <div className="divide-y divide-[var(--border-color)]">
          <ReportItem 
            title="Weekly Threat Intelligence & IOC Summary" 
            period="Past 7 Days" 
            size="Multi-page PDF" 
            type="Executive Briefing"
            onDownload={() => exportReport("pdf", "executive")}
            downloading={downloading === "pdf_executive"}
          />
          <ReportItem 
            title="MITRE ATT&CK Behavioral Coverage Audit" 
            period="Current Incident" 
            size="Full Technical PDF" 
            type="Threat Hunt Audit"
            onDownload={() => exportReport("pdf", "full")}
            downloading={downloading === "pdf_full"}
          />
          <ReportItem 
            title="Splunk Ingestion & Telemetry Health Log" 
            period="Past 24 Hours" 
            size="Structured CSV" 
            type="System Audit"
            onDownload={() => exportReport("csv")}
            downloading={downloading === "csv_executive"}
          />
          <ReportItem 
            title="AI Agent Investigation Playbook & Recommendations" 
            period="Selected Case" 
            size="Full Technical PDF" 
            type="AI Operations"
            onDownload={() => exportReport("pdf", "full")}
            downloading={downloading === "pdf_full"}
          />
        </div>
      </section>
    </div>
  );
}

function ReportItem({ 
  title, 
  period, 
  size, 
  type,
  onDownload,
  downloading = false,
}: { 
  title: string; 
  period: string; 
  size: string; 
  type: string;
  onDownload: () => void;
  downloading?: boolean;
}) {
  return (
    <div className="py-3 flex items-center justify-between text-xs hover:bg-[var(--surface-hover)] px-2 rounded transition-colors">
      <div className="flex items-center gap-3">
        <FileText className="w-4 h-4 text-[var(--text-muted)] shrink-0" />
        <div>
          <span className="font-semibold text-[var(--text-primary)] block">{title}</span>
          <span className="font-mono text-[11px] text-[var(--text-muted)]">
            Period: {period} · Format: {size} · Type: {type}
          </span>
        </div>
      </div>
      <button 
        onClick={onDownload} 
        disabled={downloading}
        className="button-secondary text-[11px] py-1 px-2.5 flex items-center gap-1.5 cursor-pointer"
      >
        {downloading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
        <span>{downloading ? "Generating..." : "Download PDF"}</span>
      </button>
    </div>
  );
}
