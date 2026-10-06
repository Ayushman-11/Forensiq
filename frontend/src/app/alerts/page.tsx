"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type React from "react";
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
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  Flame,
  FileText,
  Activity,
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

const severityStyles: Record<string, { badge: string; dot: string; label: string }> = {
  critical: {
    badge: "bg-rose-500/15 text-rose-300 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.25)]",
    dot: "bg-rose-500 shadow-[0_0_8px_#f43f5e]",
    label: "CRITICAL",
  },
  high: {
    badge: "bg-orange-500/15 text-orange-300 border-orange-500/40 shadow-[0_0_12px_rgba(249,115,22,0.2)]",
    dot: "bg-orange-500 shadow-[0_0_8px_#f97316]",
    label: "HIGH",
  },
  medium: {
    badge: "bg-sky-500/15 text-sky-300 border-sky-500/40",
    dot: "bg-sky-400",
    label: "MEDIUM",
  },
  low: {
    badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    dot: "bg-emerald-400",
    label: "LOW",
  },
};

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

  const investigate = async () => {
    if (!selected) return;
    setWorking(true);
    try {
      const r = await apiFetch(`/api/v1/alerts/${selected._id}/investigate`, { method: "POST" });
      if (!r.ok) throw new Error("Investigation could not be started");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Investigation could not be started");
    } finally {
      setWorking(false);
    }
  };

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-6 pb-12">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1E2E48] pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="dot-live" />
            <p className="label text-cyan-400 font-mono tracking-widest text-xs">INCIDENT MANAGEMENT</p>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
            Security Alerts & Triage Workspace
          </h1>
          <p className="mt-1 text-sm text-slate-300">
            Inspect indicators, review AI analysis, correlate events, and execute disposition actions.
          </p>
        </div>
        <button onClick={() => void load()} className="button-secondary cursor-pointer py-2 px-4 text-xs font-semibold">
          <RefreshCw className="h-4 w-4 text-cyan-400" />
          <span>Refresh Queue</span>
        </button>
      </header>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-5 w-5 shrink-0 text-rose-400" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <section className="card flex flex-wrap items-center gap-4 p-4 border-[#1E2E48] shadow-lg">
        <div className="relative min-w-[280px] flex-1">
          <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-cyan-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by alert title, target host, or rule name..."
            className="field w-full pl-10 h-10 bg-[#0A101C] border-[#1C2C44] focus:border-cyan-500 text-sm text-slate-100"
          />
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Filter className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="field pl-9 h-10 bg-[#0A101C] border-[#1C2C44] text-sm text-slate-200 cursor-pointer font-medium"
            >
              <option value="All">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="field h-10 bg-[#0A101C] border-[#1C2C44] text-sm text-slate-200 cursor-pointer font-medium"
          >
            <option value="All">All Statuses</option>
            <option value="New">New</option>
            <option value="Investigating">Investigating</option>
            <option value="Investigated">Investigated</option>
            <option value="Closed">Closed</option>
            <option value="Escalated">Escalated</option>
            <option value="Suppressed">Suppressed</option>
          </select>
        </div>

        <div className="border-l border-[#1E2E48] pl-4 flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-300 font-semibold">{alerts.length} alerts</span>
          <span className="text-rose-400 font-bold px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/30">
            {counts.critical ?? 0} Critical
          </span>
          <span className="text-amber-400 font-bold px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/30">
            {counts.high ?? 0} High
          </span>
        </div>
      </section>

      {/* Main Split Queue & Investigation View */}
      <section className="grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(480px,1.35fr)]">
        {/* Left: Alerts List */}
        <div className="card overflow-hidden border-[#1E2E48] flex flex-col h-[780px] shadow-xl">
          <div className="section-heading py-3.5 px-5">
            <div>
              <p className="label text-cyan-400 text-xs">Alert Feed</p>
              <h2 className="text-sm sm:text-base font-bold text-white mt-0.5">Select Alert to Inspect</h2>
            </div>
            <span className="text-xs font-mono text-slate-400 font-medium">{alerts.length} Total</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[#18263D]">
            {loading ? (
              <div className="page-state min-h-[350px]">
                <Loader2 className="h-6 w-6 animate-spin text-cyan-400" />
                <span className="text-slate-300 font-medium">Loading telemetry queue…</span>
              </div>
            ) : alerts.length === 0 ? (
              <div className="p-16 text-center text-slate-400 text-sm">
                No alerts matching the selected filters.
              </div>
            ) : (
              alerts.map((a) => {
                const sev = severityStyles[a.severity.toLowerCase()] ?? severityStyles.low;
                const isSelected = selected?._id === a._id;
                return (
                  <button
                    key={a._id}
                    onClick={() => setSelectedId(a._id)}
                    className={`flex w-full items-start gap-4 p-4 text-left transition-all cursor-pointer ${
                      isSelected
                        ? "bg-[#142238] border-l-4 border-l-cyan-400 shadow-md"
                        : "hover:bg-[#111C2E] border-l-4 border-l-transparent"
                    }`}
                  >
                    {/* Severity Pill */}
                    <div className="shrink-0 mt-0.5">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider border ${sev.badge}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                        {sev.label}
                      </span>
                    </div>

                    {/* Alert Info */}
                    <div className="min-w-0 flex-1">
                      <span className={`block text-sm font-semibold leading-snug transition-colors ${
                        isSelected ? "text-cyan-300 font-bold" : "text-white"
                      }`}>
                        {formatAlertTitle(a.title)}
                      </span>

                      {/* Metadata Chips */}
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded bg-[#16233B] text-slate-300 border border-[#223659]">
                          <Server className="w-3 h-3 text-cyan-400" />
                          {a.host ?? "Unknown Host"}
                        </span>
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded bg-[#16233B] text-slate-300 border border-[#223659] max-w-[200px] truncate">
                          <Terminal className="w-3 h-3 text-amber-400 shrink-0" />
                          <span className="truncate">{a.rule_name ?? "General Detection"}</span>
                        </span>
                      </div>
                    </div>

                    {/* Age and Status */}
                    <div className="flex flex-col items-end shrink-0 gap-1.5">
                      <span className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                        <Clock3 className="h-3.5 w-3.5 text-slate-400" />
                        {ageLabel(a.created_at)}
                      </span>
                      <span className="font-mono text-[10px] uppercase font-bold text-slate-400 px-2 py-0.5 rounded bg-[#0E1726] border border-[#1C2C44]">
                        {a.status}
                      </span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Selected Alert Detail with Tabbed Workspace */}
        <div className="card h-[780px] overflow-hidden border-[#1E2E48] flex flex-col shadow-xl">
          {selected ? (
            <AlertDetail
              alert={selected}
              working={working}
              onInvestigate={investigate}
              onClose={() => setSelectedId(null)}
              onChanged={load}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-4 p-12 text-center">
              <div className="w-16 h-16 rounded-2xl bg-[#121B2C] border border-[#23354E] flex items-center justify-center text-cyan-400 shadow-xl">
                <ShieldAlert className="h-8 w-8" />
              </div>
              <div>
                <p className="text-lg font-bold text-white">No Alert Selected</p>
                <p className="max-w-sm text-sm text-slate-400 mt-1 leading-relaxed">
                  Select an alert from the queue to inspect indicators, run AI investigation pipelines, and resolve threat incidents.
                </p>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function AlertDetail({
  alert,
  working,
  onInvestigate,
  onClose,
  onChanged,
}: {
  alert: AlertRecord;
  working: boolean;
  onInvestigate: () => void;
  onClose: () => void;
  onChanged: () => Promise<void>;
}) {
  const [activeTab, setActiveTab] = useState<"overview" | "iocs" | "telemetry">("overview");
  const [note, setNote] = useState("");
  const [jobs, setJobs] = useState<InvestigationJob[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<"full" | "executive" | null>(null);

  const downloadReport = async (type: "full" | "executive") => {
    setDownloading(type);
    setMessage(null);
    try {
      const endpoint =
        type === "full"
          ? `/api/v1/alerts/${alert._id}/report/full`
          : `/api/v1/alerts/${alert._id}/report/executive`;
      const res = await apiFetch(endpoint);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Report generation failed");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const disposition = res.headers.get("content-disposition") || "";
      const match = disposition.match(/filename="?([^"]+)"?/);
      a.download = match?.[1] ?? `forensiq_${type}_report.pdf`;
      a.href = url;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setMessage(
        type === "full"
          ? "Full investigation report downloaded successfully."
          : "Executive summary downloaded successfully."
      );
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Failed to generate report");
    } finally {
      setDownloading(null);
    }
  };

  useEffect(() => {
    let active = true;
    apiFetch(`/api/v1/alerts/${alert._id}/investigations`)
      .then((r) => (r.ok ? r.json() : []))
      .then((d: InvestigationJob[]) => {
        if (active) setJobs(d);
      })
      .catch(() => {
        if (active) setJobs([]);
      });
    return () => {
      active = false;
    };
  }, [alert._id]);

  const action = async (name: "close" | "escalate" | "suppress") => {
    const r = await apiFetch(`/api/v1/alerts/${alert._id}/disposition`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: name, note: note || undefined }),
    });
    if (!r.ok) {
      setMessage("Disposition update failed");
      return;
    }
    setNote("");
    setMessage(`Alert marked as ${name}d`);
    await onChanged();
  };

  const addNote = async () => {
    if (!note.trim()) return;
    const r = await apiFetch(`/api/v1/alerts/${alert._id}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: note }),
    });
    if (r.ok) {
      setNote("");
      setMessage("Analyst note saved successfully");
    }
  };

  const sev = severityStyles[alert.severity.toLowerCase()] ?? severityStyles.low;
  const timeline = alert.timeline ?? [];
  const correlations = alert.correlations ?? [];
  const iocCount = alert.evidence?.ioc_count ?? alert.extracted_iocs?.length ?? 0;

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[#0C1322]">
      {/* Detail Top Header */}
      <div className="border-b border-[#1A2942] p-5 bg-[#0E1726]">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-2">
              <span className={`inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-xs font-extrabold uppercase tracking-wider border ${sev.badge}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                {sev.label}
              </span>
              <span className="font-mono text-xs px-3 py-0.5 rounded-full bg-[#16243A] text-slate-200 border border-[#223554] font-semibold">
                Status: {alert.status}
              </span>
            </div>
            
            <h2 className="text-base sm:text-lg font-bold text-white leading-snug">
              {formatAlertTitle(alert.title)}
            </h2>

            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs font-mono text-slate-300">
              <span>Target: <strong className="text-cyan-400 font-semibold">{alert.host ?? "Unknown Host"}</strong></span>
              <span>·</span>
              <span>Account: <strong className="text-amber-400 font-semibold">{alert.user ?? "SYSTEM"}</strong></span>
            </div>
          </div>

          <button
            onClick={onClose}
            aria-label="Close detail"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#1A2942] transition-colors cursor-pointer shrink-0"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Toolbar: Scores and Disposition Actions */}
        <div className="mt-4 pt-3.5 border-t border-[#16243A] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400 font-medium">Risk Score:</span>
              <span className="font-mono text-sm font-extrabold text-rose-400 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30">
                {alert.risk_score ?? "—"}/100
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-slate-400 font-medium">AI Confidence:</span>
              <span className="font-mono text-sm font-extrabold text-cyan-300 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30">
                {alert.ai_confidence ?? "—"}%
              </span>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            {(alert.status === "New" || alert.status === "Investigation Failed") && (
              <button
                onClick={onInvestigate}
                disabled={working}
                className="button-primary cursor-pointer text-xs py-1.5 px-3"
              >
                {working ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                <span>AI Investigate</span>
              </button>
            )}

            <button
              onClick={() => void action("close")}
              className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 text-xs font-semibold cursor-pointer transition-colors"
            >
              Close
            </button>
            <button
              onClick={() => void action("escalate")}
              className="px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20 text-xs font-semibold cursor-pointer transition-colors"
            >
              Escalate
            </button>
            <button
              onClick={() => void action("suppress")}
              className="px-3 py-1.5 rounded-lg bg-[#16233B] border border-[#223554] text-slate-300 hover:bg-[#1E304E] text-xs font-semibold cursor-pointer transition-colors"
            >
              Suppress
            </button>

            {/* ── Report Export Buttons ── */}
            <div className="flex items-center gap-1.5 border-l border-[#1E2E48] pl-2">
              <button
                id="btn-download-exec-summary"
                onClick={() => void downloadReport("executive")}
                disabled={downloading !== null}
                title="Download one-page executive summary PDF"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-500/10 border border-violet-500/30 text-violet-300 hover:bg-violet-500/20 text-xs font-semibold cursor-pointer transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {downloading === "executive" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <FileDown className="h-3.5 w-3.5" />
                )}
                <span>{downloading === "executive" ? "Generating…" : "Exec Summary"}</span>
              </button>

              <button
                id="btn-download-full-report"
                onClick={() => void downloadReport("full")}
                disabled={downloading !== null}
                title="Download full investigation report PDF"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 text-xs font-semibold cursor-pointer transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {downloading === "full" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Download className="h-3.5 w-3.5" />
                )}
                <span>{downloading === "full" ? "Generating…" : "Full Report"}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-[#1A2942] bg-[#0A101C] px-5">
        <button
          onClick={() => setActiveTab("overview")}
          className={`flex items-center gap-2 py-3 px-4 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
            activeTab === "overview"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Overview & AI Analysis</span>
        </button>

        <button
          onClick={() => setActiveTab("iocs")}
          className={`flex items-center gap-2 py-3 px-4 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
            activeTab === "iocs"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Radar className="w-3.5 h-3.5" />
          <span>IOC Intelligence ({iocCount})</span>
        </button>

        <button
          onClick={() => setActiveTab("telemetry")}
          className={`flex items-center gap-2 py-3 px-4 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
            activeTab === "telemetry"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Braces className="w-3.5 h-3.5" />
          <span>Context & Splunk Event</span>
        </button>
      </div>

      {/* Tab Content Panes */}
      <div className="flex-1 overflow-y-auto p-5">
        {message && (
          <div className="mb-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 font-medium">
            {message}
          </div>
        )}

        {/* TAB 1: OVERVIEW */}
        {activeTab === "overview" && (
          <div className="space-y-5">
            {/* AI Recommendation Box */}
            {alert.recommendation ? (
              <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/30 via-slate-900 to-sky-950/20 p-5 shadow-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <p className="label text-cyan-400 font-bold text-xs">AI Agent Recommendation</p>
                </div>
                <p className="text-sm text-slate-100 leading-relaxed font-medium">
                  {alert.recommendation}
                </p>
              </div>
            ) : (
              <div className="rounded-xl border border-[#1E2E48] bg-[#0E1626] p-4 text-xs text-slate-400 flex items-center justify-between">
                <span>No automated investigation has been performed yet on this alert.</span>
                <button onClick={onInvestigate} className="button-primary text-xs py-1 px-3">
                  Run Investigation
                </button>
              </div>
            )}

            {/* 3 Metric Mini Cards */}
            <div className="grid gap-4 sm:grid-cols-3">
              <MetricCard 
                label="Extracted Evidence" 
                value={String(iocCount)} 
                sub="Indicators of Compromise"
              />
              <MetricCard 
                label="Correlated Events" 
                value={String(correlations.length)} 
                sub="Matching Cross-Alerts"
              />
              <MetricCard 
                label="MITRE Mappings" 
                value={String(alert.mitre_mappings?.length ?? (alert.mitre_technique ? 1 : 0))} 
                sub="Tactic & Techniques"
              />
            </div>

            {/* Attack Timeline */}
            {timeline.length > 0 && (
              <div className="card p-5 border-[#1E2E48]">
                <p className="label text-cyan-400 text-xs mb-3 font-bold">Attack Progression Timeline</p>
                <div className="space-y-3.5 pl-2">
                  {timeline.map((e, i) => (
                    <div key={i} className="border-l-2 border-cyan-500/60 pl-4 relative">
                      <span className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
                      <p className="text-xs sm:text-sm font-semibold text-white">{e.description}</p>
                      <p className="font-mono text-xs text-slate-400 mt-0.5">
                        {e.timestamp} · Source: {e.source}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Analyst Note Section */}
            <div className="card p-5 border-[#1E2E48]">
              <p className="label text-slate-300 text-xs mb-2 font-bold">Analyst Case Notes</p>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Document your findings, escalation reasons, or notes for the SOC audit trail…"
                className="field min-h-24 w-full p-3.5 text-xs sm:text-sm bg-[#090E17] border-[#1C2C44] text-slate-100 rounded-lg leading-relaxed"
              />
              <div className="mt-3 flex justify-end">
                <button onClick={() => void addNote()} className="button-secondary cursor-pointer py-2 px-4 text-xs font-semibold">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  <span>Save Analyst Note</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: IOC INTELLIGENCE (Full Width) */}
        {activeTab === "iocs" && (
          <div className="h-full">
            <EnrichmentPanel alert={alert} />
          </div>
        )}

        {/* TAB 3: CONTEXT & TELEMETRY (Full Width) */}
        {activeTab === "telemetry" && (
          <div className="h-full">
            <ContextPanel alert={alert} />
          </div>
        )}
      </div>
    </div>
  );
}

function MetricCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="card p-4 border-[#1E2E48] bg-[#0E1626]">
      <p className="label text-slate-400 text-xs">{label}</p>
      <p className="mt-1.5 font-mono text-2xl sm:text-3xl font-extrabold text-white tracking-tight">{value}</p>
      {sub && <p className="text-xs text-slate-400 mt-1 font-medium">{sub}</p>}
    </div>
  );
}

