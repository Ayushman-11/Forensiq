"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { 
  Activity, 
  ArrowRight, 
  CircleAlert, 
  Clock3, 
  RefreshCw, 
  ShieldCheck,
  AlertTriangle,
  Flame,
  CheckCircle2,
  BellRing,
  Database,
  Radio,
  Cpu,
  Server,
  Terminal,
  Zap
} from "lucide-react";
import { apiFetch } from "@/lib/api";

type Metrics = {
  total_alerts: number;
  new_alerts: number;
  critical_alerts: number;
  high_priority_alerts: number;
  open_investigations: number;
  investigated_alerts: number;
  ai_confidence_avg: number;
  last_ingested_at?: string | null;
};

type Alert = { 
  _id: string; 
  title: string; 
  severity: string; 
  status: string; 
  host?: string; 
  rule_name?: string; 
  created_at: string; 
  risk_score?: number; 
  priority?: string 
};

type TimelinePoint = { hour: string; count: number };

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
  // Strip duplicate bracketed severity tags like "[CRITICAL] " since badge is already shown
  return title.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i, "").trim();
}

function ageLabel(value: string) {
  const diffMs = Date.now() - new Date(value).getTime();
  const minutes = Math.max(0, Math.round(diffMs / 60000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [ingesting, setIngesting] = useState(false);
  const [ingestMsg, setIngestMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setRefreshing(true);
      setError(null);
      const [metricsRes, alertsRes, timelineRes] = await Promise.all([
        apiFetch("/api/v1/dashboard/metrics"),
        apiFetch("/api/v1/alerts?limit=6&status=New"),
        apiFetch("/api/v1/alerts/stats/timeline"),
      ]);

      if (!metricsRes.ok || !alertsRes.ok || !timelineRes.ok) {
        throw new Error("Unable to load SOC telemetry data");
      }

      setMetrics((await metricsRes.json()) as Metrics);
      setAlerts((await alertsRes.json()) as Alert[]);
      setTimeline((await timelineRes.json()) as TimelinePoint[]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load SOC telemetry data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const triggerIngest = async () => {
    try {
      setIngesting(true);
      setIngestMsg(null);
      const res = await apiFetch("/api/v1/alerts/ingest", { method: "POST" });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail?.message || "Ingestion request failed");
      }
      const data = await res.json();
      setIngestMsg(`Sync complete: ${data.inserted ?? 0} new alert(s) ingested from Splunk`);
      await load(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Splunk ingestion error");
    } finally {
      setIngesting(false);
      setTimeout(() => setIngestMsg(null), 6000);
    }
  };

  useEffect(() => {
    void load();
    const interval = setInterval(() => void load(true), 30000);
    return () => clearInterval(interval);
  }, [load]);

  const maxCount = useMemo(() => Math.max(...timeline.map((point) => point.count), 1), [timeline]);
  const totalVolume = useMemo(() => timeline.reduce((sum, point) => sum + point.count, 0), [timeline]);
  const peakPoint = useMemo(() => {
    if (!timeline.length) return null;
    return timeline.reduce((max, curr) => (curr.count > max.count ? curr : max), timeline[0]);
  }, [timeline]);

  const lastIngested = metrics?.last_ingested_at 
    ? new Date(metrics.last_ingested_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: 'numeric' })
    : "Live polling";

  if (loading && !metrics) {
    return (
      <div className="page-state">
        <Activity className="h-6 w-6 animate-pulse text-cyan-400" />
        <span className="text-slate-300 font-medium">Initializing Security Operations Command Center…</span>
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-[1480px] flex-col gap-6 pb-12">
      {/* Dashboard Top Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1E2E48] pb-6">
        <div>
          <div className="flex items-center gap-2.5 mb-1.5">
            <span className="dot-live" />
            <p className="label text-cyan-400 font-mono tracking-widest">
              SOC OPERATIONS / LIVE TELEMETRY
            </p>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            Security Triage Command Center
          </h1>
          <p className="mt-1.5 text-sm sm:text-base text-slate-300">
            Real-time threat detection, automated AI IOC enrichment, and attack timeline analysis.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          <button 
            onClick={triggerIngest} 
            disabled={ingesting}
            className="button-primary cursor-pointer py-2.5 px-4 text-sm"
            title="Poll Splunk Enterprise for new security events"
          >
            <Zap className={`h-4.5 w-4.5 ${ingesting ? "animate-spin text-amber-300" : "text-cyan-300"}`} />
            <span>{ingesting ? "Ingesting from Splunk…" : "Sync Splunk Alerts"}</span>
          </button>

          <button 
            onClick={() => void load()} 
            disabled={refreshing}
            className="button-secondary cursor-pointer py-2.5 px-4 text-sm" 
            aria-label="Refresh dashboard"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin text-cyan-400" : ""}`} /> 
            <span>Refresh</span>
          </button>
        </div>
      </header>

      {/* Notifications / Alerts */}
      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {ingestMsg && (
        <div className="flex items-center gap-2.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-xs font-semibold text-emerald-300 shadow-md">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>{ingestMsg}</span>
        </div>
      )}

      {/* KPI Metric Cards */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4" aria-label="Queue summary">
        <MetricCard 
          label="Needs Review"
          value={metrics?.new_alerts ?? 0}
          note="Incoming unassigned alerts"
          icon={BellRing}
          tone="amber"
          highlight="Queue Pending"
        />
        <MetricCard 
          label="Priority Threats"
          value={metrics?.high_priority_alerts ?? 0}
          note="Critical & high severity"
          icon={AlertTriangle}
          tone="critical"
          highlight="Requires Escalation"
        />
        <MetricCard 
          label="Active Investigations"
          value={metrics?.open_investigations ?? 0}
          note="LangGraph AI agents running"
          icon={Cpu}
          tone="accent"
          highlight="Pipeline Working"
        />
        <MetricCard 
          label="Resolved / Triaged"
          value={metrics?.investigated_alerts ?? 0}
          note={`Out of ${metrics?.total_alerts ?? 0} total ingested`}
          icon={ShieldCheck}
          tone="success"
          highlight="Evidence Generated"
        />
      </section>

      {/* Main Grid: Triage Queue & Telemetry Health */}
      <section className="grid gap-5 lg:grid-cols-[minmax(0,1.75fr)_minmax(330px,0.95fr)]">
        {/* Triage Queue List */}
        <div className="card overflow-hidden border-[#1E2E48]">
          <div className="section-heading">
            <div className="flex items-center gap-2.5">
              <div className="w-2 h-2 rounded-full bg-cyan-400" />
              <div>
                <p className="label text-cyan-400">Real-Time Threat Queue</p>
                <h2 className="section-title">New Detections Pending Triage</h2>
              </div>
            </div>
            <Link 
              href="/alerts?status=New" 
              className="link-action font-semibold"
            >
              <span>View Full Queue</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>

          {alerts.length === 0 ? (
            <div className="p-12 text-center">
              <ShieldCheck className="h-10 w-10 text-emerald-400/60 mx-auto mb-3" />
              <p className="text-sm font-semibold text-slate-200">The Triage Queue is Clear</p>
              <p className="mt-1 text-xs text-slate-300">All ingested alerts have been investigated or resolved.</p>
            </div>
          ) : (
            <div className="divide-y divide-[#18263D]">
              {alerts.map((alert) => {
                const sev = severityStyles[alert.severity.toLowerCase()] ?? severityStyles.low;
                return (
                  <Link 
                    href={`/alerts?alert=${encodeURIComponent(alert._id)}`} 
                    key={alert._id} 
                    className="alert-row group hover:bg-[#131E33] transition-all"
                  >
                    {/* Severity Pill */}
                    <div className="shrink-0">
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wider border ${sev.badge}`}>
                        <span className={`w-2 h-2 rounded-full ${sev.dot}`} />
                        {sev.label}
                      </span>
                    </div>

                    {/* Alert Information */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="block truncate text-base font-bold text-white group-hover:text-cyan-300 transition-colors">
                          {formatAlertTitle(alert.title)}
                        </span>
                      </div>
                      
                      {/* Subtitle Tags */}
                      <div className="mt-2 flex flex-wrap items-center gap-2.5">
                        <span className="inline-flex items-center gap-1.5 font-mono text-xs px-2.5 py-1 rounded bg-[#16233B] text-slate-200 border border-[#223659] font-medium">
                          <Server className="w-3.5 h-3.5 text-cyan-400" />
                          {alert.host ?? "Unknown Host"}
                        </span>
                        <span className="inline-flex items-center gap-1.5 font-mono text-xs px-2.5 py-1 rounded bg-[#16233B] text-slate-200 border border-[#223659] font-medium">
                          <Terminal className="w-3.5 h-3.5 text-amber-400" />
                          {alert.rule_name ?? "General Detection"}
                        </span>
                      </div>
                    </div>

                    {/* Timestamp & Action */}
                    <div className="flex shrink-0 items-center gap-4">
                      <span className="flex items-center gap-1.5 font-mono text-sm font-semibold text-slate-300">
                        <Clock3 className="h-4 w-4 text-slate-400" />
                        {ageLabel(alert.created_at)}
                      </span>
                      <div className="w-8 h-8 rounded-lg bg-[#16243A] border border-[#223554] flex items-center justify-center text-slate-300 group-hover:text-cyan-300 group-hover:border-cyan-500/40 group-hover:bg-[#1A2C46] transition-all">
                        <ArrowRight className="h-4 w-4" />
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>

        {/* Telemetry & System Status Card */}
        <div className="card p-6 border-[#1E2E48] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-[#1A2942]">
              <div>
                <p className="label text-cyan-400 text-xs font-bold tracking-wider">SIEM PIPELINE</p>
                <h2 className="text-xl font-bold text-white tracking-tight mt-1">Telemetry & Signal</h2>
              </div>
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-md">
                <Radio className="w-5 h-5 animate-pulse" />
              </div>
            </div>

            <div className="mt-6 space-y-6">
              <SignalLine 
                label="Splunk Ingestion" 
                value={lastIngested} 
                subtext="Status: Streaming"
                tone="green"
              />
              
              <div className="space-y-2 border-b border-[#16243A] pb-4">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-200 font-semibold">AI Investigation Confidence</span>
                  <span className="font-mono font-bold text-base text-cyan-300">{metrics?.ai_confidence_avg ?? 0}%</span>
                </div>
                <div className="w-full h-2.5 rounded-full bg-[#142034] overflow-hidden border border-[#1E2E48]">
                  <div 
                    className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-sky-400 to-emerald-400 transition-all duration-500 shadow-[0_0_10px_rgba(6,182,212,0.4)]"
                    style={{ width: `${Math.min(Math.max(metrics?.ai_confidence_avg ?? 0, 8), 100)}%` }}
                  />
                </div>
                <p className="text-xs text-slate-400 font-medium">Based on multi-source threat intelligence matching</p>
              </div>

              <SignalLine 
                label="Retained Alerts" 
                value={`${metrics?.total_alerts ?? 0} events`} 
                subtext="MongoDB Atlas Storage"
                tone="blue"
              />
            </div>
          </div>

          <div className="mt-8 pt-5 border-t border-[#1A2942]">
            <Link 
              href="/search" 
              className="button-secondary w-full justify-center py-3 text-sm font-semibold text-slate-100 hover:text-white"
            >
              <Terminal className="h-4 w-4 text-cyan-400" />
              <span>Query Raw Telemetry in SPL</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* 24-Hour Detection Volume Bar Chart */}
      <section className="card p-6 border-[#1E2E48]">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-[#1A2942]">
          <div>
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              <p className="label text-cyan-400">Attack Velocity</p>
            </div>
            <h2 className="text-lg font-bold text-white mt-0.5">24-Hour Detection Volume</h2>
          </div>
          <div className="flex items-center gap-3">
            {peakPoint && (
              <span className="font-mono text-sm px-3 py-1 rounded-md bg-[#16233B] text-amber-300 border border-amber-500/30">
                Peak: <strong>{peakPoint.count}</strong> @ {peakPoint.hour}
              </span>
            )}
            <span className="font-mono text-sm px-3 py-1 rounded-md bg-[#16233B] text-cyan-300 border border-cyan-500/30">
              Total: <strong>{totalVolume}</strong> events
            </span>
          </div>
        </div>

        {timeline.length === 0 ? (
          <div className="py-12 text-center text-sm text-slate-300 font-medium">
            No detection telemetry recorded in the last 24 hours.
          </div>
        ) : (
          <div className="mt-6 flex h-44 items-end gap-1.5 sm:gap-2 px-1">
            {timeline.map((point) => {
              const heightPct = Math.max((point.count / maxCount) * 100, 4);
              const isPeak = point.count === maxCount && maxCount > 0;
              return (
                <div 
                  key={point.hour} 
                  className="group flex h-full flex-1 flex-col justify-end gap-2 cursor-pointer" 
                  title={`${point.hour}: ${point.count} alerts`}
                >
                  <div className="relative flex flex-col items-center justify-end h-full">
                    {/* Hover Tooltip */}
                    <div className="absolute -top-8 hidden group-hover:flex px-2 py-1 rounded bg-[#1F3354] text-white font-mono text-xs font-bold shadow-lg border border-cyan-500/40 z-20 whitespace-nowrap">
                      {point.count} alerts
                    </div>

                    {/* Bar */}
                    <div 
                      className={`w-full rounded-t-sm transition-all duration-200 group-hover:opacity-100 ${
                        isPeak 
                          ? "bg-gradient-to-t from-rose-500 to-amber-400 opacity-90 shadow-[0_0_10px_rgba(244,63,94,0.4)]" 
                          : "bg-gradient-to-t from-sky-600 to-cyan-400 opacity-75 group-hover:from-sky-500 group-hover:to-cyan-300"
                      }`} 
                      style={{ height: `${heightPct}%` }} 
                    />
                  </div>
                  <span className="truncate text-center font-mono text-xs text-slate-300 group-hover:text-cyan-300 transition-colors font-medium">
                    {point.hour}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

function MetricCard({ 
  label, 
  value, 
  note, 
  icon: Icon, 
  tone,
  highlight 
}: { 
  label: string; 
  value: number; 
  note: string; 
  icon: React.ComponentType<{ className?: string }>; 
  tone: "amber" | "critical" | "accent" | "success";
  highlight: string;
}) {
  const toneConfig = {
    amber: {
      border: "border-t-2 border-t-amber-500",
      iconBg: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      valueColor: "text-amber-400",
      badge: "bg-amber-500/10 text-amber-300 border-amber-500/30",
    },
    critical: {
      border: "border-t-2 border-t-rose-500",
      iconBg: "bg-rose-500/10 text-rose-400 border-rose-500/30",
      valueColor: "text-rose-400",
      badge: "bg-rose-500/10 text-rose-300 border-rose-500/30",
    },
    accent: {
      border: "border-t-2 border-t-cyan-500",
      iconBg: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
      valueColor: "text-cyan-400",
      badge: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
    },
    success: {
      border: "border-t-2 border-t-emerald-500",
      iconBg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      valueColor: "text-emerald-400",
      badge: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
    },
  }[tone];

  return (
    <div className={`card p-5.5 ${toneConfig.border} border-[#1E2E48] hover:border-[#2C4266] transition-all relative overflow-hidden group shadow-lg`}>
      <div className="flex items-center justify-between">
        <p className="label text-slate-200 font-bold text-xs tracking-wider">{label}</p>
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center border ${toneConfig.iconBg}`}>
          <Icon className="w-4.5 h-4.5" />
        </div>
      </div>
      
      <div className="mt-3.5 flex items-baseline justify-between">
        <p className={`font-mono text-4xl sm:text-5xl font-extrabold tracking-tight ${toneConfig.valueColor}`}>
          {value.toLocaleString()}
        </p>
      </div>

      <div className="mt-3 flex items-center justify-between gap-2 border-t border-[#16243A] pt-3">
        <p className="text-sm text-slate-300 font-medium truncate">{note}</p>
        <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded border shrink-0 ${toneConfig.badge}`}>
          {highlight}
        </span>
      </div>
    </div>
  );
}

function SignalLine({ 
  label, 
  value, 
  subtext,
  tone 
}: { 
  label: string; 
  value: string; 
  subtext?: string;
  tone: "green" | "blue";
}) {
  const dotColor = tone === "green" ? "bg-emerald-400 shadow-[0_0_10px_#10b981]" : "bg-cyan-400 shadow-[0_0_10px_#38bdf8]";
  return (
    <div className="flex items-start justify-between gap-3 border-b border-[#16243A] pb-3.5">
      <div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${dotColor}`} />
          <span className="text-sm font-semibold text-slate-100">{label}</span>
        </div>
        {subtext && <p className="text-xs text-slate-400 font-medium ml-4 mt-0.5">{subtext}</p>}
      </div>
      <span className="text-right font-mono text-sm font-semibold text-slate-100 max-w-[60%] truncate">
        {value}
      </span>
    </div>
  );
}

