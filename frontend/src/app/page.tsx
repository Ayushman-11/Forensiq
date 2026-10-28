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
  CheckCircle2,
  Terminal,
  Zap,
  Server,
  Layers,
  Cpu
} from "lucide-react";
import { apiFetch } from "@/lib/api";
import MitreMatrix from "@/components/mitre/MitreMatrix";
import SocMetricsPanel from "@/components/triage/SocMetricsPanel";
import { STATE_COLOR, STATE_LABEL, useSystemHealth, type ComponentState } from "@/lib/health";

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

function formatAlertTitle(title: string) {
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
  const [refreshKey, setRefreshKey] = useState(0);
  const { health, unreachable: healthUnreachable, refresh: refreshHealth } = useSystemHealth();

  const load = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setRefreshing(true);
      setError(null);
      const summaryRes = await apiFetch("/api/v1/dashboard/summary");
      if (summaryRes.ok) {
        const summary = await summaryRes.json();
        setMetrics(summary.metrics as Metrics);
        setAlerts(summary.recent_alerts as Alert[]);
        setTimeline(summary.timeline as TimelinePoint[]);
      } else {
        const [metricsRes, alertsRes, timelineRes] = await Promise.all([
          apiFetch("/api/v1/dashboard/metrics"),
          apiFetch("/api/v1/alerts?limit=6&status=open&assignee=unassigned&sort=severity"),
          apiFetch("/api/v1/alerts/stats/timeline"),
        ]);
        if (!metricsRes.ok || !alertsRes.ok || !timelineRes.ok) {
          throw new Error("Unable to load SOC telemetry data");
        }
        setMetrics((await metricsRes.json()) as Metrics);
        setAlerts((await alertsRes.json()) as Alert[]);
        setTimeline((await timelineRes.json()) as TimelinePoint[]);
      }
      void refreshHealth();
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load SOC telemetry data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [refreshHealth]);

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

  if (loading && !metrics) {
    return (
      <div className="page-state">
        <Activity className="h-5 w-5 animate-spin text-[var(--text-muted)]" />
        <span>Loading Security Operations Console…</span>
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-[1440px] flex-col gap-6 pb-12">
      {/* Top Header Section */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Dashboard
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Security operations · Real-time detection, investigation and response.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={triggerIngest}
            disabled={ingesting}
            className="button-primary text-xs"
          >
            <Zap className={`h-3.5 w-3.5 ${ingesting ? "animate-spin" : ""}`} />
            <span>{ingesting ? "Ingesting..." : "Sync Splunk"}</span>
          </button>

          <button
            onClick={() => void load()}
            disabled={refreshing}
            className="button-secondary text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {ingestMsg && (
        <div className="flex items-center gap-2 rounded border border-[#22C55E]/30 bg-[#22C55E]/10 px-3.5 py-2 text-xs font-medium text-[#22C55E]">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{ingestMsg}</span>
        </div>
      )}

      {/* Section 7: Top KPI Cards (Vercel Monochrome with Semantic Color Numbers) */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KPICard
          title="Critical Alerts"
          value={metrics?.critical_alerts} 
          semanticColor="#EF4444"
          subtext="Requires immediate triage"
        />
        <KPICard
          title="Open Critical + High"
          value={metrics?.high_priority_alerts}
          semanticColor="#F59E0B"
          subtext="Not yet closed or suppressed"
        />
        <KPICard
          title="Active Investigations"
          value={metrics?.open_investigations}
          semanticColor="#3B82F6"
          subtext="Pipeline runs in progress"
        />
        <KPICard
          title="Investigated"
          value={metrics?.investigated_alerts}
          semanticColor="#22C55E"
          subtext={metrics ? `Out of ${metrics.total_alerts} ingested` : "Unavailable"}
        />
      </section>

      <SocMetricsPanel refreshKey={refreshKey} />

      {/* Grid: Alert Activity Chart & System Health */}
      <section className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        {/* Section 8: Alert Activity Bar Chart */}
        <div className="card p-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border-color)]">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">Alert Activity</h2>
              <p className="text-xs text-[var(--text-muted)]">Alerts detected per hour, last 24h (UTC)</p>
            </div>
            <span className="font-mono text-xs text-[var(--text-secondary)] font-medium">
              Total: {totalVolume} alerts
            </span>
          </div>

          <div className="mt-4 flex h-40 items-end gap-2 px-2">
            {timeline.length === 0 ? (
              <div className="w-full flex items-center justify-center text-xs text-[var(--text-muted)]">
                No alerts detected in the past 24h
              </div>
            ) : (
              timeline.map((point) => {
                const heightPct = Math.max((point.count / maxCount) * 100, 6);
                const color = "#3B82F6";
                return (
                  <div key={point.hour} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                    <div
                      className="w-full rounded-t-sm transition-opacity group-hover:opacity-80"
                      style={{ height: `${heightPct}%`, backgroundColor: color }}
                      title={`${point.hour}: ${point.count} alerts`}
                    />
                    <span className="font-mono text-[10px] text-[var(--text-muted)] truncate">
                      {point.hour}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Section 10: System Health */}
        <div className="card p-4 flex flex-col justify-between">
          <div>
            <div className="pb-3 border-b border-[var(--border-color)]">
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">System Health</h2>
              <p className="text-xs text-[var(--text-muted)]">
                {health ? `Checked ${ageLabel(health.checked_at)}` : healthUnreachable ? "Health endpoint unreachable" : "Checking…"}
              </p>
            </div>

            <div className="mt-4 space-y-3">
              <HealthStatusItem label="Splunk" state={health?.siem.state} detail={health?.siem.detail} />
              <HealthStatusItem label="Ingestion" state={health?.ingestion.state} detail={health?.ingestion.detail} />
              <HealthStatusItem label="AI Engine" state={health?.ai.state} detail={health?.ai.detail} />
              <HealthStatusItem
                label="Threat Intel"
                state={health?.threat_intel.state}
                detail={health?.threat_intel.feeds.map((f) => `${f.feed}: ${STATE_LABEL[f.state]}`).join(" · ")}
              />
            </div>
          </div>

          <div className="mt-6 pt-3 border-t border-[var(--border-color)]">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--text-secondary)]">
                Avg assessment confidence{health?.ai.mode === "rules" ? " (rules engine)" : ""}
              </span>
              <span className="font-mono font-semibold text-[var(--text-primary)]">
                {metrics ? `${metrics.ai_confidence_avg}%` : "—"}
              </span>
            </div>
            <div className="w-full h-1.5 bg-[var(--surface-elevated)] rounded-full overflow-hidden mt-1.5">
              <div
                className="h-full bg-[#8B5CF6]"
                style={{ width: `${metrics?.ai_confidence_avg ?? 0}%` }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* Interactive MITRE ATT&CK Matrix */}
      <section>
        <MitreMatrix />
      </section>

      {/* New Detections Pending Triage */}
      <section>
        <div className="card p-4 flex flex-col justify-between">
          <div>
            <div className="pb-3 border-b border-[var(--border-color)] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[var(--text-primary)]">Unassigned open alerts</h2>
                <p className="text-xs text-[var(--text-muted)]">Highest severity first. Pick one up from the queue.</p>
              </div>
              <Link href="/alerts?view=unassigned" className="button-secondary text-xs flex items-center gap-1.5 cursor-pointer">
                <span>View Full Alerts Queue</span> <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="mt-3 divide-y divide-[var(--border-color)]">
              {alerts.length === 0 ? (
                <p className="text-xs text-[var(--text-muted)] py-6 text-center">No unassigned open alerts</p>
              ) : (
                alerts.slice(0, 4).map((a) => (
                  <Link
                    key={a._id}
                    href={`/alerts/${encodeURIComponent(a._id)}`}
                    className="py-2.5 flex items-center justify-between text-xs hover:bg-[var(--surface-hover)] px-1 rounded transition-colors group"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        a.severity === 'critical' ? 'bg-[#EF4444]' : a.severity === 'high' ? 'bg-[#F59E0B]' : a.severity === 'medium' ? 'bg-[#3B82F6]' : 'bg-[#94A3B8]'
                      }`} />
                      <span className="font-medium text-[var(--text-primary)] truncate group-hover:underline">
                        {formatAlertTitle(a.title)}
                      </span>
                    </div>
                    <span className="font-mono text-[11px] text-[var(--text-muted)] shrink-0 ml-2">
                      {ageLabel(a.created_at)}
                    </span>
                  </Link>
                ))
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-[var(--border-color)] mt-4">
            <Link href="/search" className="button-secondary w-full justify-center text-xs">
              <Terminal className="w-3.5 h-3.5" />
              <span>Query Raw Telemetry in SPL</span>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}

function KPICard({
  title,
  value,
  semanticColor,
  subtext
}: {
  title: string;
  value: number | undefined;
  semanticColor: string;
  subtext: string;
}) {
  return (
    <div className="card p-4 flex flex-col justify-between">
      <span className="text-xs font-medium text-[var(--text-secondary)]">{title}</span>
      <div className="mt-2 flex items-baseline justify-between">
        <span
          className="font-mono text-3xl font-bold tracking-tight"
          style={{ color: semanticColor }}
        >
          {value === undefined ? "—" : value.toLocaleString()}
        </span>
      </div>
      <span className="text-[11px] text-[var(--text-muted)] mt-2 pt-2 border-t border-[var(--border-color)]">
        {subtext}
      </span>
    </div>
  );
}

function HealthStatusItem({ label, state, detail }: { label: string; state?: ComponentState; detail?: string }) {
  return (
    <div className="flex items-start justify-between gap-3 text-xs">
      <span className="text-[var(--text-primary)] font-medium">{label}</span>
      <div className="flex flex-col items-end min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: state ? STATE_COLOR[state] : "#94A3B8" }} />
          <span className="font-mono text-[11px] text-[var(--text-secondary)]">{state ? STATE_LABEL[state] : "Unknown"}</span>
        </div>
        {detail && <span className="text-[10px] text-[var(--text-muted)] text-right truncate max-w-[220px]" title={detail}>{detail}</span>}
      </div>
    </div>
  );
}
