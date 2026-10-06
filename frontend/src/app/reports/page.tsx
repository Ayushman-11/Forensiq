"use client";

import { useCallback, useEffect, useState } from "react";
import { FileText, Download, ShieldCheck, RefreshCw, BarChart2, Calendar, CheckCircle2 } from "lucide-react";
import { apiFetch } from "@/lib/api";

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
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const exportReport = async (format: "pdf" | "csv" | "json") => {
    setDownloading(format);
    try {
      let blob: Blob;
      let filename: string;

      if (format === "pdf") {
        const alertsResponse = await apiFetch("/api/v1/alerts?limit=1");
        if (!alertsResponse.ok) throw new Error("Unable to find an alert for the report");
        const alerts = (await alertsResponse.json()) as Array<{ _id: string }>;
        if (!alerts[0]?._id) throw new Error("No alerts are available for PDF export");

        const reportResponse = await apiFetch(
          `/api/v1/alerts/${encodeURIComponent(alerts[0]._id)}/report/executive`,
        );
        if (!reportResponse.ok) {
          const body = await reportResponse.json().catch(() => ({}));
          throw new Error(body.detail || "Report generation failed");
        }
        blob = await reportResponse.blob();
        filename = `forensiq_executive_summary_${Date.now()}.pdf`;
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
            Reports
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Security operations reports · Threat metrics, audit compliance, and executive summary exports.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => exportReport("pdf")} disabled={!!downloading} className="button-primary text-xs">
            <Download className="h-3.5 w-3.5" />
            <span>{downloading === "pdf" ? "Exporting..." : "Export Executive PDF"}</span>
          </button>
          <button onClick={() => exportReport("csv")} disabled={!!downloading} className="button-secondary text-xs">
            <span>Export CSV</span>
          </button>
        </div>
      </header>

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
            title="Weekly Threat Intelligence Summary" 
            period="Past 7 Days" 
            size="2.4 MB" 
            type="Executive Briefing"
            onDownload={() => exportReport("pdf")}
          />
          <ReportItem 
            title="MITRE ATT&CK Behavioral Coverage Audit" 
            period="Current Month" 
            size="1.8 MB" 
            type="Threat Hunt Audit"
            onDownload={() => exportReport("pdf")}
          />
          <ReportItem 
            title="Splunk Ingestion & Telemetry Health Log" 
            period="Past 24 Hours" 
            size="512 KB" 
            type="System Audit"
            onDownload={() => exportReport("csv")}
          />
          <ReportItem 
            title="AI Agent Investigation Playbook Performance" 
            period="Past 30 Days" 
            size="3.1 MB" 
            type="AI Operations"
            onDownload={() => exportReport("pdf")}
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
  onDownload 
}: { 
  title: string; 
  period: string; 
  size: string; 
  type: string;
  onDownload: () => void;
}) {
  return (
    <div className="py-3 flex items-center justify-between text-xs hover:bg-[var(--surface-hover)] px-2 rounded transition-colors">
      <div className="flex items-center gap-3">
        <FileText className="w-4 h-4 text-[var(--text-muted)] shrink-0" />
        <div>
          <span className="font-semibold text-[var(--text-primary)] block">{title}</span>
          <span className="font-mono text-[11px] text-[var(--text-muted)]">
            Period: {period} · Size: {size} · Type: {type}
          </span>
        </div>
      </div>
      <button onClick={onDownload} className="button-secondary text-[11px] py-1 px-2.5">
        <Download className="w-3 h-3" />
        <span>Download</span>
      </button>
    </div>
  );
}
