"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { CircleAlert, Clock3, Filter, Loader2, Play, RefreshCw, Search, X } from "lucide-react";
import ContextPanel from "@/components/investigation/ContextPanel";
import EnrichmentPanel from "@/components/investigation/EnrichmentPanel";
import { apiFetch } from "@/lib/api";

type Alert = {
  _id: string; title: string; severity: string; status: string; host?: string; user?: string;
  rule_name?: string; alert_type?: string; created_at: string; ai_confidence?: number;
  risk_score?: number; priority?: string; recommendation?: string; enrichments?: unknown[];
  extracted_iocs?: string[]; context?: Record<string, string>; [key: string]: unknown;
};

const severityClass: Record<string, string> = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low" };

function ageLabel(value: string) {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const params = new URLSearchParams({ limit: "100" });
      if (search) params.set("search", search);
      if (severity !== "All") params.set("severity", severity);
      if (status !== "All") params.set("status", status);
      const res = await apiFetch(`/api/v1/alerts?${params.toString()}`);
      if (!res.ok) throw new Error("Unable to load alert queue");
      const next = (await res.json()) as Alert[];
      setAlerts(next);
      if (selected) setSelected(next.find((alert) => alert._id === selected._id) ?? null);
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to load alert queue"); }
    finally { setLoading(false); }
  }, [search, severity, status, selected]);

  useEffect(() => { const initial = setTimeout(() => void load(), 0); const interval = setInterval(() => void load(), 30000); return () => { clearTimeout(initial); clearInterval(interval); }; }, [load]);

  const counts = useMemo(() => alerts.reduce<Record<string, number>>((out, alert) => { out[alert.severity] = (out[alert.severity] ?? 0) + 1; return out; }, {}), [alerts]);

  const investigate = async () => {
    if (!selected) return;
    setWorking(true);
    try {
      const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(selected._id)}/investigate`, { method: "POST" });
      if (!res.ok) throw new Error("Investigation could not be started");
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Investigation could not be started"); }
    finally { setWorking(false); }
  };

  return (
    <div className="mx-auto flex max-w-[1440px] flex-col gap-5 pb-10">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--color-border)] pb-5">
        <div><p className="label mb-2">Operations / queue</p><h1 className="text-2xl font-bold tracking-tight text-[var(--color-text)]">Alerts</h1><p className="mt-1 text-sm text-[var(--color-text-muted)]">Triage detections, then open one investigation at a time.</p></div>
        <button onClick={() => void load()} className="button-secondary"><RefreshCw className="h-4 w-4" /> Refresh</button>
      </header>

      {error && <div className="feedback-error"><CircleAlert className="h-4 w-4" />{error}</div>}
      <section className="card flex flex-wrap items-center gap-3 p-3">
        <div className="relative min-w-[240px] flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-text-dim)]" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title or host" className="field pl-10" /></div>
        <div className="relative"><Filter className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--color-text-dim)]" /><select value={severity} onChange={(event) => setSeverity(event.target.value)} className="field appearance-none pl-9 pr-8"><option>All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div>
        <div className="relative"><select value={status} onChange={(event) => setStatus(event.target.value)} className="field appearance-none pr-8"><option>All</option><option>New</option><option>Investigating</option><option>Investigated</option><option>Investigation Failed</option></select></div>
        <div className="flex items-center gap-2 border-l border-[var(--color-border)] pl-3 text-xs text-[var(--color-text-muted)]"><span>{alerts.length} shown</span>{counts.critical ? <span className="status-badge sev-critical">{counts.critical} critical</span> : null}</div>
      </section>

      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(360px,0.65fr)]">
        <div className="card overflow-hidden">
          <div className="section-heading"><div><p className="label">Detection queue</p><h2 className="section-title">Select an alert to inspect</h2></div><span className="text-xs text-[var(--color-text-muted)]">Auto-refresh 30s</span></div>
          {loading ? <div className="page-state min-h-[300px]"><Loader2 className="h-5 w-5 animate-spin" /> Loading queue…</div> : alerts.length === 0 ? <div className="p-10 text-center text-sm text-[var(--color-text-muted)]">No alerts match these filters.</div> : <div className="divide-y divide-[var(--color-border)]">{alerts.map((alert) => <button key={alert._id} onClick={() => setSelected(alert)} className={`flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-[var(--color-surface-2)] ${selected?._id === alert._id ? "bg-[var(--color-surface-2)]" : ""}`}><span className={`status-badge ${severityClass[alert.severity] ?? "sev-low"}`}>{alert.severity}</span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold text-[var(--color-text)]">{alert.title}</span><span className="mt-1 block truncate font-mono text-[11px] text-[var(--color-text-muted)]">{alert.host ?? "Unknown host"} · {alert.rule_name ?? "Unclassified detection"}</span></span><span className="flex shrink-0 items-center gap-1.5 font-mono text-[11px] text-[var(--color-text-muted)]"><Clock3 className="h-3.5 w-3.5" />{ageLabel(alert.created_at)}</span></button>)}</div>}
        </div>

        <div className="card min-h-[500px] overflow-hidden">
          {!selected ? <div className="flex h-full min-h-[500px] flex-col items-center justify-center gap-3 p-8 text-center"><CircleAlert className="h-8 w-8 text-[var(--color-text-dim)]" /><p className="text-sm font-semibold text-[var(--color-text-muted)]">No alert selected</p><p className="max-w-xs text-xs text-[var(--color-text-dim)]">Select a detection to see the evidence that matters before taking action.</p></div> : <AlertDetail alert={selected} working={working} onInvestigate={investigate} onClose={() => setSelected(null)} />}
        </div>
      </section>
    </div>
  );
}

function AlertDetail({ alert, working, onInvestigate, onClose }: { alert: Alert; working: boolean; onInvestigate: () => void; onClose: () => void }) {
  const canInvestigate = alert.status === "New" || alert.status === "Investigation Failed";
  return <div className="flex h-full flex-col"><div className="flex items-start justify-between border-b border-[var(--color-border)] p-5"><div><p className="label mb-2">Selected detection</p><h2 className="text-lg font-bold leading-snug text-[var(--color-text)]">{alert.title}</h2><p className="mt-2 font-mono text-[11px] text-[var(--color-text-muted)]">{alert.host ?? "Unknown host"} · {alert.user ?? "Unknown user"}</p></div><button onClick={onClose} className="text-[var(--color-text-muted)] hover:text-[var(--color-text)]" aria-label="Close detail"><X className="h-4 w-4" /></button></div><div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] p-4"><span className={`status-badge ${severityClass[alert.severity] ?? "sev-low"}`}>{alert.severity}</span><span className="status-badge border border-[var(--color-border)] text-[var(--color-text-muted)]">{alert.status}</span>{alert.risk_score !== undefined ? <span className="text-xs text-[var(--color-text-muted)]">Risk <strong className="text-[var(--color-text)]">{alert.risk_score}/100</strong></span> : null}<span className="ml-auto font-mono text-[11px] text-[var(--color-text-muted)]">{ageLabel(alert.created_at)}</span></div>{canInvestigate && <div className="border-b border-[var(--color-border)] p-4"><button onClick={onInvestigate} disabled={working} className="button-primary">{working ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} {working ? "Starting…" : "Investigate alert"}</button></div>}<div className="flex-1 space-y-4 overflow-y-auto p-4">{alert.recommendation ? <div className="rounded border border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5 p-3"><p className="label">Recommended next step</p><p className="mt-2 text-sm text-[var(--color-text)]">{alert.recommendation}</p></div> : null}<div className="grid gap-4 xl:grid-cols-2"><ContextPanel alert={alert} /><EnrichmentPanel alert={alert} /></div></div></div>;
}
