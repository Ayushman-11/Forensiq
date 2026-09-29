"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Activity, ArrowRight, CircleAlert, Clock3, RefreshCw, ShieldCheck } from "lucide-react";
import { apiFetch } from "@/lib/api";

type Metrics = {
  total_alerts: number; new_alerts: number; critical_alerts: number;
  high_priority_alerts: number; open_investigations: number;
  investigated_alerts: number; ai_confidence_avg: number; last_ingested_at?: string | null;
};
type Alert = { _id: string; title: string; severity: string; status: string; host?: string; rule_name?: string; created_at: string; risk_score?: number; priority?: string };
type TimelinePoint = { hour: string; count: number };

const severityClass: Record<string, string> = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low" };

function ageLabel(value: string) {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [metricsRes, alertsRes, timelineRes] = await Promise.all([
        apiFetch("/api/v1/dashboard/metrics"), apiFetch("/api/v1/alerts?limit=6&status=New"), apiFetch("/api/v1/alerts/stats/timeline"),
      ]);
      if (!metricsRes.ok || !alertsRes.ok || !timelineRes.ok) throw new Error("Unable to load SOC data");
      setMetrics((await metricsRes.json()) as Metrics);
      setAlerts((await alertsRes.json()) as Alert[]);
      setTimeline((await timelineRes.json()) as TimelinePoint[]);
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to load SOC data"); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { const initial = setTimeout(() => void load(), 0); const interval = setInterval(() => void load(), 30000); return () => { clearTimeout(initial); clearInterval(interval); }; }, [load]);

  const maxCount = useMemo(() => Math.max(...timeline.map((point) => point.count), 1), [timeline]);
  const lastIngested = metrics?.last_ingested_at ? new Date(metrics.last_ingested_at).toLocaleString() : "Not available";

  if (loading && !metrics) return <div className="page-state"><Activity className="h-5 w-5 animate-pulse" /> Loading operational view…</div>;

  return (
    <div className="mx-auto flex max-w-[1440px] flex-col gap-6 pb-10">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--color-border)] pb-5">
        <div><p className="label mb-2">Operations / overview</p><h1 className="text-2xl font-bold tracking-tight text-[var(--color-text)]">What needs attention?</h1><p className="mt-1 text-sm text-[var(--color-text-muted)]">A decision-first view of the current detection queue.</p></div>
        <button onClick={() => void load()} className="button-secondary" aria-label="Refresh dashboard"><RefreshCw className="h-4 w-4" /> Refresh</button>
      </header>
      {error && <div className="feedback-error"><CircleAlert className="h-4 w-4" />{error}</div>}

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-label="Queue summary">
        <SummaryCard label="Needs review" value={metrics?.new_alerts ?? 0} note="new alerts" tone="warning" />
        <SummaryCard label="Priority queue" value={metrics?.high_priority_alerts ?? 0} note="critical + high" tone="danger" />
        <SummaryCard label="In progress" value={metrics?.open_investigations ?? 0} note="active investigations" tone="accent" />
        <SummaryCard label="Investigated" value={metrics?.investigated_alerts ?? 0} note={`of ${metrics?.total_alerts ?? 0} total`} tone="success" />
      </section>

      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.5fr)_minmax(300px,0.75fr)]">
        <div className="card overflow-hidden">
          <div className="section-heading"><div><p className="label">Triage queue</p><h2 className="section-title">New detections</h2></div><Link href="/alerts?status=New" className="link-action">Open queue <ArrowRight className="h-3.5 w-3.5" /></Link></div>
          {alerts.length === 0 ? <EmptyState message="No new detections. The queue is clear." /> : <div className="divide-y divide-[var(--color-border)]">{alerts.map((alert) => <Link href={`/alerts?alert=${encodeURIComponent(alert._id)}`} key={alert._id} className="alert-row group"><span className={`status-badge ${severityClass[alert.severity] ?? "sev-low"}`}>{alert.severity}</span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold text-[var(--color-text)] group-hover:text-[var(--color-accent)]">{alert.title}</span><span className="mt-1 block truncate font-mono text-[11px] text-[var(--color-text-muted)]">{alert.host ?? "Unknown host"} · {alert.rule_name ?? "Unclassified detection"}</span></span><span className="flex shrink-0 items-center gap-1.5 font-mono text-[11px] text-[var(--color-text-muted)]"><Clock3 className="h-3.5 w-3.5" />{ageLabel(alert.created_at)}</span></Link>)}</div>}
        </div>
        <div className="card p-5"><div className="section-heading p-0"><div><p className="label">Telemetry</p><h2 className="section-title">System signal</h2></div><ShieldCheck className="h-5 w-5 text-[var(--color-success)]" /></div><div className="mt-5 space-y-4"><InfoLine label="Last ingestion cursor" value={lastIngested} /><InfoLine label="Average confidence" value={`${metrics?.ai_confidence_avg ?? 0}%`} /><InfoLine label="Total retained alerts" value={String(metrics?.total_alerts ?? 0)} /></div><Link href="/search" className="button-secondary mt-6 w-full justify-center">Inspect raw telemetry <ArrowRight className="h-4 w-4" /></Link></div>
      </section>

      <section className="card p-5"><div className="section-heading p-0"><div><p className="label">Last 24 hours</p><h2 className="section-title">Detection volume</h2></div><span className="text-xs text-[var(--color-text-muted)]">{timeline.reduce((sum, point) => sum + point.count, 0)} events</span></div>{timeline.length === 0 ? <EmptyState message="No detection volume recorded in the last 24 hours." /> : <div className="mt-6 flex h-28 items-end gap-1.5">{timeline.map((point) => <div key={point.hour} className="group flex h-full flex-1 flex-col justify-end gap-1" title={`${point.hour}: ${point.count}`}><div className="min-h-1 rounded-sm bg-[var(--color-accent)] opacity-75 transition-opacity group-hover:opacity-100" style={{ height: `${Math.max((point.count / maxCount) * 100, 3)}%` }} /><span className="truncate text-center font-mono text-[9px] text-[var(--color-text-dim)]">{point.hour}</span></div>)}</div>}</section>
    </div>
  );
}

function SummaryCard({ label, value, note, tone }: { label: string; value: number; note: string; tone: "warning" | "danger" | "accent" | "success" }) { const color = { warning: "text-[var(--color-high)]", danger: "text-[var(--color-critical)]", accent: "text-[var(--color-accent)]", success: "text-[var(--color-success)]" }[tone]; return <div className="card p-4"><p className="label">{label}</p><p className={`mt-3 text-3xl font-bold ${color}`}>{value}</p><p className="mt-1 text-xs text-[var(--color-text-muted)]">{note}</p></div>; }
function InfoLine({ label, value }: { label: string; value: string }) { return <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] pb-3"><span className="text-xs text-[var(--color-text-muted)]">{label}</span><span className="max-w-[65%] text-right font-mono text-xs text-[var(--color-text)]">{value}</span></div>; }
function EmptyState({ message }: { message: string }) { return <div className="p-8 text-center text-sm text-[var(--color-text-muted)]">{message}</div>; }
