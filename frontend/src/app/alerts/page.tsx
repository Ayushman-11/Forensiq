"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { 
  CircleAlert, 
  Clock3, 
  Filter, 
  Loader2, 
  Play, 
  RefreshCw, 
  Search, 
  X, 
  Server, 
  Terminal, 
  ShieldAlert,
  ArrowRight,
  Eye,
  CheckCircle,
  Layers,
  Braces,
  Radar,
  Download,
  FileDown
} from "lucide-react";
import ContextPanel from "@/components/investigation/ContextPanel";
import EnrichmentPanel from "@/components/investigation/EnrichmentPanel";
import InvestigationModal from "@/components/investigation/InvestigationModal";
import { apiFetch } from "@/lib/api";
import type { AlertRecord, InvestigationJob } from "@/lib/types";

function formatAlertTitle(title: string) {
  return title.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i, "").trim();
}

function ageLabel(v: string) {
  const m = Math.max(0, Math.round((Date.now() - new Date(v).getTime()) / 60000));
  if (m < 1) return "Just now";
  if (m < 60) return `${m}m ago`;
  const hours = Math.round(m / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export default function AlertsPage() {
  const searchParams = useSearchParams();
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [investigatingAlert, setInvestigatingAlert] = useState<AlertRecord | null>(null);

  const selected = useMemo(
    () => (selectedId ? alerts.find((a) => a._id === selectedId) ?? null : alerts[0] ?? null),
    [alerts, selectedId]
  );

  const load = useCallback(async () => {
    try {
      setError(null);
      const p = new URLSearchParams({ limit: "100" });
      if (search.trim()) p.set("search", search.trim());
      if (severity !== "All") p.set("severity", severity);
      if (status !== "All") p.set("status", status);
      const r = await apiFetch(`/api/v1/alerts?${p}`);
      if (!r.ok) throw new Error("Unable to load alert queue");
      const next = (await r.json()) as AlertRecord[];
      setAlerts(next);
      const requestedAlertId = searchParams.get("alert");
      setSelectedId((prev) => {
        if (requestedAlertId && next.some((a) => a._id === requestedAlertId)) return requestedAlertId;
        if (prev && next.some((a) => a._id === prev)) return prev;
        return next.length > 0 ? next[0]._id : null;
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load alert queue");
    } finally {
      setLoading(false);
    }
  }, [search, searchParams, severity, status]);

  useEffect(() => {
    const t = setTimeout(() => void load(), 0);
    return () => clearTimeout(t);
  }, [load]);

  const counts = useMemo(
    () =>
      alerts.reduce<Record<string, number>>((o, a) => {
        const s = a.severity.toLowerCase();
        o[s] = (o[s] ?? 0) + 1;
        return o;
      }, {}),
    [alerts]
  );

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-5 pb-12">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Alerts
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Security alert queue · Real-time triage, AI investigation, and disposition.
          </p>
        </div>
        <button onClick={() => void load()} className="button-secondary text-xs">
          <RefreshCw className="h-3.5 w-3.5 text-[var(--text-muted)]" />
          <span>Refresh</span>
        </button>
      </header>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0 text-[#EF4444]" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <section className="card flex flex-wrap items-center gap-3 p-3">
        <div className="relative min-w-[260px] flex-1">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by title, host, or rule name..."
            className="field w-full pl-9 h-8 text-xs"
          />
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1 bg-[var(--surface-secondary)] p-0.5 rounded border border-[var(--border-color)]">
          {["All", "critical", "high", "medium", "low"].map((sev) => {
            const isSelected = severity === sev;
            return (
              <button
                key={sev}
                onClick={() => setSeverity(sev)}
                className={`px-2.5 py-1 rounded text-xs font-medium capitalize transition-colors ${
                  isSelected
                    ? "bg-[var(--surface-primary)] text-[var(--text-primary)] shadow-sm font-semibold"
                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}
              >
                {sev}
              </button>
            );
          })}
        </div>

        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="field h-8 text-xs cursor-pointer"
        >
          <option value="All">All Statuses</option>
          <option value="New">New</option>
          <option value="Investigating">Investigating</option>
          <option value="Investigated">Investigated</option>
          <option value="Closed">Closed</option>
          <option value="Escalated">Escalated</option>
        </select>

        <div className="border-l border-[var(--border-color)] pl-3 flex items-center gap-2 text-xs font-mono">
          <span className="text-[var(--text-muted)]">{alerts.length} total</span>
          <span className="text-[#EF4444] font-semibold">{counts.critical ?? 0} Critical</span>
          <span className="text-[#F59E0B] font-semibold">{counts.high ?? 0} High</span>
        </div>
      </section>

      {/* Main Alert Table View */}
      <section className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--surface-secondary)] text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                <th className="py-2.5 px-4 w-28">Severity</th>
                <th className="py-2.5 px-4">Title</th>
                <th className="py-2.5 px-4 w-44">Target Host</th>
                <th className="py-2.5 px-4 w-48">Detection Rule</th>
                <th className="py-2.5 px-4 w-28">Time</th>
                <th className="py-2.5 px-4 w-32">Status</th>
                <th className="py-2.5 px-4 w-36 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-color)] text-xs">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[var(--text-muted)]">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                    <span>Loading alert queue...</span>
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[var(--text-muted)]">
                    No alerts match the selected filters.
                  </td>
                </tr>
              ) : (
                alerts.map((a) => {
                  const isSelected = selected?._id === a._id;
                  const sevColor = 
                    a.severity === 'critical' ? '#EF4444' :
                    a.severity === 'high' ? '#F59E0B' :
                    a.severity === 'medium' ? '#3B82F6' : '#94A3B8';
                  
                  return (
                    <tr 
                      key={a._id}
                      onClick={() => setSelectedId(a._id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected 
                          ? "bg-[var(--sidebar-active-bg)]" 
                          : "hover:bg-[var(--surface-hover)]"
                      }`}
                    >
                      {/* Severity badge */}
                      <td className="py-3 px-4">
                        <span 
                          className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase border"
                          style={{
                            color: sevColor,
                            borderColor: `${sevColor}40`,
                            backgroundColor: `${sevColor}10`
                          }}
                        >
                          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: sevColor }} />
                          {a.severity}
                        </span>
                      </td>

                      {/* Title */}
                      <td className="py-3 px-4">
                        <span className="font-semibold text-[var(--text-primary)] block truncate max-w-lg">
                          {formatAlertTitle(a.title)}
                        </span>
                      </td>

                      {/* Target Host */}
                      <td className="py-3 px-4 font-mono text-[var(--text-secondary)]">
                        {a.host || "Unknown"}
                      </td>

                      {/* Rule Name */}
                      <td className="py-3 px-4 font-mono text-[var(--text-muted)] truncate max-w-[180px]">
                        {a.rule_name || "General Detection"}
                      </td>

                      {/* Time */}
                      <td className="py-3 px-4 font-mono text-[var(--text-muted)] whitespace-nowrap">
                        {ageLabel(a.created_at)}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4">
                        <span className="font-mono text-[10px] uppercase font-semibold text-[var(--text-secondary)] px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-color)]">
                          {a.status}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setInvestigatingAlert(a)}
                            className="button-primary text-[11px] py-1 px-2.5"
                          >
                            <Play className="w-3 h-3" />
                            <span>Investigate</span>
                          </button>
                          <button
                            onClick={() => setSelectedId(a._id)}
                            className="button-secondary text-[11px] py-1 px-2.5"
                          >
                            <Eye className="w-3 h-3" />
                            <span>View</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Selected Alert Details View */}
      {selected && (
        <section className="card p-5 mt-2">
          <AlertDetailSection 
            alert={selected} 
            onInvestigate={() => setInvestigatingAlert(selected)}
            onReload={load}
          />
        </section>
      )}

      {/* LangGraph Live Investigation Modal */}
      {investigatingAlert && (
        <InvestigationModal
          alert={investigatingAlert}
          isOpen={!!investigatingAlert}
          onClose={() => setInvestigatingAlert(null)}
          onComplete={async () => {
            await load();
          }}
        />
      )}
    </div>
  );
}

function AlertDetailSection({ 
  alert, 
  onInvestigate, 
  onReload 
}: { 
  alert: AlertRecord; 
  onInvestigate: () => void; 
  onReload: () => Promise<void>; 
}) {
  const [activeTab, setActiveTab] = useState<"overview" | "iocs" | "telemetry">("overview");
  const [downloading, setDownloading] = useState<"full" | "executive" | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  const downloadReport = async (type: "full" | "executive") => {
    setDownloading(type);
    setReportError(null);
    try {
      const endpoint = type === "full"
        ? `/api/v1/alerts/${alert._id}/report/full`
        : `/api/v1/alerts/${alert._id}/report/executive`;
      const response = await apiFetch(endpoint);
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || "Report generation failed");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `forensiq_${type}_report.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setReportError(error instanceof Error ? error.message : "Report generation failed");
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs uppercase font-semibold text-[var(--text-muted)]">
              {alert.severity} • {alert.status}
            </span>
          </div>
          <h2 className="text-base font-bold text-[var(--text-primary)] mt-0.5">
            {formatAlertTitle(alert.title)}
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => void downloadReport("executive")} disabled={downloading !== null} className="button-secondary text-xs">
            {downloading === "executive" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}
            <span>{downloading === "executive" ? "Generating..." : "Exec Summary"}</span>
          </button>
          <button onClick={() => void downloadReport("full")} disabled={downloading !== null} className="button-secondary text-xs">
            {downloading === "full" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            <span>{downloading === "full" ? "Generating..." : "Full Report"}</span>
          </button>
          <button onClick={onInvestigate} className="button-primary text-xs">
            <Play className="w-3.5 h-3.5" />
            <span>Start AI Pipeline</span>
          </button>
        </div>
      </div>
      {reportError && <p className="text-xs text-[#EF4444]">{reportError}</p>}

      {/* Tab Navigation */}
      <div className="flex border-b border-[var(--border-color)]">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "overview"
              ? "border-[var(--text-primary)] text-[var(--text-primary)]"
              : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
          }`}
        >
          Overview & Analysis
        </button>
        <button
          onClick={() => setActiveTab("iocs")}
          className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "iocs"
              ? "border-[var(--text-primary)] text-[var(--text-primary)]"
              : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
          }`}
        >
          IOC Intelligence ({alert.extracted_iocs?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab("telemetry")}
          className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "telemetry"
              ? "border-[var(--text-primary)] text-[var(--text-primary)]"
              : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
          }`}
        >
          Extracted Context & Raw Payload
        </button>
      </div>

      <div>
        {activeTab === "overview" && (
          <div className="space-y-4">
            {alert.recommendation && (
              <div className="p-3.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] text-xs text-[var(--text-primary)]">
                <span className="font-semibold block mb-1">AI Response Playbook:</span>
                {alert.recommendation}
              </div>
            )}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
                <span className="text-[11px] text-[var(--text-muted)] block">Target Host</span>
                <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">{alert.host || "N/A"}</span>
              </div>
              <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
                <span className="text-[11px] text-[var(--text-muted)] block">Target User</span>
                <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">{alert.user || "SYSTEM"}</span>
              </div>
              <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
                <span className="text-[11px] text-[var(--text-muted)] block">Risk Score</span>
                <span className="font-mono text-xs font-bold text-[#EF4444]">{alert.risk_score ?? "—"}/100</span>
              </div>
            </div>
          </div>
        )}

        {activeTab === "iocs" && <EnrichmentPanel alert={alert} />}
        {activeTab === "telemetry" && <ContextPanel alert={alert} />}
      </div>
    </div>
  );
}
