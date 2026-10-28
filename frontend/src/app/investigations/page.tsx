"use client";

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { 
  ShieldAlert, 
  Activity, 
  CheckCircle2, 
  Clock, 
  Cpu, 
  FileText, 
  Play, 
  RefreshCw, 
  Search, 
  Server, 
  ArrowRight,
  Database,
  Crosshair,
  Sparkles,
  Download,
  FileDown,
  Loader2,
} from "lucide-react";
import { apiFetch } from "@/lib/api";
import type { AlertRecord } from "@/lib/types";
import InvestigationModal from "@/components/investigation/InvestigationModal";
import ProcessTreeGraph from "@/components/investigation/ProcessTreeGraph";


const PIPELINE_STAGES = [
  { key: "context", label: "Context" },
  { key: "enrichment", label: "Enrichment" },
  { key: "correlation", label: "Correlation" },
  { key: "mitre", label: "MITRE" },
  { key: "timeline", label: "Timeline" },
  { key: "risk", label: "Risk" },
  { key: "recommendation", label: "Recommendation" },
];

export default function InvestigationsPage() {
  const searchParams = useSearchParams();
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigatingAlert, setInvestigatingAlert] = useState<AlertRecord | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState<"full" | "executive" | null>(null);

  const downloadReport = async (type: "full" | "executive") => {
    if (!selectedAlert) return;
    setDownloadingPdf(type);
    try {
      const endpoint = `/api/v1/alerts/${encodeURIComponent(selectedAlert._id)}/report/pdf?report_type=${type}`;
      const response = await apiFetch(endpoint);
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || "PDF report generation failed");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forensiq_${type === "full" ? "investigation_report" : "executive_summary"}_${selectedAlert._id.slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      console.error("PDF download failed:", err);
      if (typeof window !== "undefined") {
        window.alert(err instanceof Error ? err.message : "Failed to download PDF report");
      }
    } finally {

      setDownloadingPdf(null);
    }
  };


  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/api/v1/alerts?limit=50");
      if (res.ok) {
        const data = (await res.json()) as AlertRecord[];
        setAlerts(data);
        const requestedId = searchParams.get("alert");
        if (requestedId) {
          const matched = data.find((a) => a._id === requestedId);
          if (matched) {
            setSelectedAlert(matched);
            return;
          }
        }
        if (data.length > 0 && !selectedAlert) {
          setSelectedAlert(data[0]);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [searchParams, selectedAlert]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-6 pb-12">
      {/* Page Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Investigations
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            AI Agent Pipeline · Multi-stage automated incident analysis and playbook generation.
          </p>
        </div>
        <button onClick={() => void load()} className="button-secondary text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Refresh</span>
        </button>
      </header>

      {/* Section 14: Extraction Pipeline Visualization Banner */}
      <section className="card p-4">
        <div className="flex items-center justify-between mb-3 border-b border-[var(--border-color)] pb-2">
          <span className="text-xs font-semibold text-[var(--text-primary)]">
            LangGraph Agent Execution Pipeline
          </span>
          <span className="font-mono text-[11px] text-[var(--text-muted)]">7 Autonomous Nodes</span>
        </div>

        <div className="flex items-center justify-between py-2 overflow-x-auto px-4">
          {PIPELINE_STAGES.map((stage, idx) => {
            const isCompleted = selectedAlert?.status === "Investigated";
            const isRunning = selectedAlert?.status === "Investigating";
            const isCurrent = idx === (isRunning ? 2 : isCompleted ? 6 : 0);

            return (
              <div key={stage.key} className="flex items-center gap-3 shrink-0">
                <div className="flex flex-col items-center gap-1.5">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-mono font-bold border transition-colors ${
                    isCompleted 
                      ? "bg-[#22C55E]/10 border-[#22C55E] text-[#22C55E]" 
                      : isCurrent 
                      ? "bg-[#3B82F6]/10 border-[#3B82F6] text-[#3B82F6]" 
                      : "bg-[var(--surface-elevated)] border-[var(--border-color)] text-[var(--text-muted)]"
                  }`}>
                    {idx + 1}
                  </div>
                  <span className="text-[11px] font-medium text-[var(--text-secondary)]">{stage.label}</span>
                </div>
                {idx < PIPELINE_STAGES.length - 1 && (
                  <div className={`h-0.5 w-12 sm:w-16 ${
                    idx < (isCompleted ? 6 : isRunning ? 2 : 0) ? "bg-[#22C55E]" : "bg-[var(--border-color)]"
                  }`} />
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Two Column Layout (Section 13: Clean Vercel-style) */}
      <section className="grid gap-5 lg:grid-cols-[340px_minmax(0,1fr)]">
        {/* Left: Investigation Cases List */}
        <div className="card p-3 flex flex-col h-[700px] overflow-hidden">
          <div className="pb-2.5 border-b border-[var(--border-color)] px-1 flex items-center justify-between">
            <span className="text-xs font-semibold text-[var(--text-primary)]">Active & Prior Cases</span>
            <span className="font-mono text-[11px] text-[var(--text-muted)]">{alerts.length}</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[var(--border-color)] mt-1">
            {loading ? (
              <div className="py-12 text-center text-xs text-[var(--text-muted)]">Loading investigations...</div>
            ) : (
              alerts.map((a) => {
                const isSelected = selectedAlert?._id === a._id;
                return (
                  <button
                    key={a._id}
                    onClick={() => setSelectedAlert(a)}
                    className={`w-full text-left p-2.5 rounded transition-colors ${
                      isSelected 
                        ? "bg-[var(--sidebar-active-bg)] font-semibold" 
                        : "hover:bg-[var(--surface-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-[10px] text-[var(--text-muted)] uppercase">{a.severity}</span>
                      <span className="font-mono text-[10px] text-[var(--text-secondary)]">{a.status}</span>
                    </div>
                    <p className="text-xs text-[var(--text-primary)] mt-1 font-medium truncate">
                      {a.title}
                    </p>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Selected Investigation Workflow Detail */}
        <div className="card p-5 h-[700px] overflow-y-auto">
          {selectedAlert ? (
            <div className="space-y-5">
              {/* Header Toolbar */}
              <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
                <div>
                  <span className="text-[11px] font-mono text-[var(--text-muted)] uppercase">
                    Host: {selectedAlert.host || "Unknown"} · User: {selectedAlert.user || "SYSTEM"}
                  </span>
                  <h2 className="text-base font-bold text-[var(--text-primary)] mt-0.5">
                    {selectedAlert.title}
                  </h2>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => void downloadReport("executive")}
                    disabled={downloadingPdf !== null}
                    className="button-secondary text-xs flex items-center gap-1.5 cursor-pointer"
                    title="Download 1-page executive summary PDF"
                  >
                    {downloadingPdf === "executive" ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <FileDown className="w-3.5 h-3.5" />
                    )}
                    <span>{downloadingPdf === "executive" ? "Generating..." : "Exec PDF"}</span>
                  </button>
                  <button
                    onClick={() => void downloadReport("full")}
                    disabled={downloadingPdf !== null}
                    className="button-secondary text-xs flex items-center gap-1.5 cursor-pointer"
                    title="Download full multi-page investigation report PDF"
                  >
                    {downloadingPdf === "full" ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Download className="w-3.5 h-3.5" />
                    )}
                    <span>{downloadingPdf === "full" ? "Generating..." : "Full Report PDF"}</span>
                  </button>
                  <button
                    onClick={() => setInvestigatingAlert(selectedAlert)}
                    className="button-primary text-xs flex items-center gap-1.5 cursor-pointer"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Run Agent Pipeline</span>
                  </button>
                </div>

              </div>

              {/* Sections: Summary, Evidence, Behaviors, ATT&CK, Timeline, Recommendation */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
                  <span className="text-[11px] text-[var(--text-muted)] block">Risk Assessment</span>
                  <span className="font-mono text-lg font-bold text-[#EF4444]">{selectedAlert.risk_score ?? "—"}/100</span>
                </div>
                <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
                  <span className="text-[11px] text-[var(--text-muted)] block">Extracted Evidence</span>
                  <span className="font-mono text-lg font-bold text-[var(--text-primary)]">{selectedAlert.extracted_iocs?.length || 0} IOCs</span>
                </div>
                <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
                  <span className="text-[11px] text-[var(--text-muted)] block">AI Confidence</span>
                  <span className="font-mono text-lg font-bold text-[#8B5CF6]">{selectedAlert.ai_confidence ?? "—"}%</span>
                </div>
              </div>

              {/* Visual Process Execution Tree */}
              <div className="space-y-2">
                <ProcessTreeGraph alert={selectedAlert} />
              </div>

              {/* Summary & Playbook */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-[var(--text-primary)]">AI Playbook Recommendation</h3>
                <div className="p-3.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] text-xs text-[var(--text-primary)] leading-relaxed font-mono">
                  {selectedAlert.recommendation || "No AI investigation performed yet. Click 'Run Agent Pipeline' to execute multi-agent triage."}
                </div>
              </div>

              {/* Timeline */}
              {selectedAlert.timeline && selectedAlert.timeline.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-[var(--text-primary)]">Attack Chronology</h3>
                  <div className="space-y-2 pl-2 border-l border-[var(--border-color)]">
                    {selectedAlert.timeline.map((item, idx) => (
                      <div key={idx} className="pl-3 relative text-xs">
                        <span className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-[var(--text-primary)]" />
                        <p className="font-medium text-[var(--text-primary)]">{item.description}</p>
                        <p className="font-mono text-[10px] text-[var(--text-muted)]">{item.timestamp} · {item.source}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="py-24 text-center text-xs text-[var(--text-muted)]">Select a case from the sidebar</div>
          )}
        </div>
      </section>

      {investigatingAlert && (
        <InvestigationModal
          alert={investigatingAlert}
          isOpen={!!investigatingAlert}
          onClose={() => setInvestigatingAlert(null)}
          onComplete={async (updated) => {
            setSelectedAlert(updated);
            await load();
          }}
        />
      )}
    </div>
  );
}
