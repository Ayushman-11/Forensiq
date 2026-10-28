"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch } from "@/lib/api";
import { VERDICT_LABELS, type Verdict } from "@/lib/triage";

type SocMetrics = {
  window_days: number;
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  acknowledged: number;
  resolved: number;
  open_by_severity: Record<string, number>;
  unassigned_open: number;
  sla_breached: { acknowledge: number; resolve: number };
  open_aging: { lt_1h: number; "1h_24h": number; "1d_7d": number; gt_7d: number };
  verdicts: Record<string, number>;
  rule_precision: { rule: string; closed: number; true_positive: number; false_positive: number; precision: number | null }[];
};

function duration(minutes: number | null): string {
  if (minutes == null) return "—";
  if (minutes < 60) return `${Math.round(minutes)}m`;
  if (minutes < 1440) return `${(minutes / 60).toFixed(1)}h`;
  return `${(minutes / 1440).toFixed(1)}d`;
}

const AGING_LABELS: [keyof SocMetrics["open_aging"], string][] = [
  ["lt_1h", "< 1h"],
  ["1h_24h", "1–24h"],
  ["1d_7d", "1–7d"],
  ["gt_7d", "> 7d"],
];

export default function SocMetricsPanel({ refreshKey }: { refreshKey: number }) {
  const [days, setDays] = useState(7);
  const [metrics, setMetrics] = useState<SocMetrics | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiFetch(`/api/v1/dashboard/soc-metrics?days=${days}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((m: SocMetrics) => {
        if (!cancelled) {
          setMetrics(m);
          setFailed(false);
        }
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [days, refreshKey]);

  const openTotal = metrics ? Object.values(metrics.open_by_severity).reduce((a, b) => a + b, 0) : 0;
  const decided = metrics ? Object.values(metrics.verdicts).reduce((a, b) => a + b, 0) : 0;

  return (
    <section className="card p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-color)] pb-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Analyst workflow</h2>
          <p className="text-xs text-[var(--text-muted)]">From assignments, notes and verdicts. MTTA/MTTR are medians from detection.</p>
        </div>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="field h-8 text-xs cursor-pointer" aria-label="Metrics window">
          <option value={1}>Last 24h</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
        </select>
      </div>

      {failed && <p className="text-xs text-[#EF4444]">Unable to load workflow metrics.</p>}

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-5">
        <Tile label="MTTA" value={duration(metrics?.mtta_minutes ?? null)} sub={metrics ? `${metrics.acknowledged} acknowledged` : ""} />
        <Tile label="MTTR" value={duration(metrics?.mttr_minutes ?? null)} sub={metrics ? `${metrics.resolved} resolved` : ""} />
        <Tile
          label="Open"
          value={metrics ? String(openTotal) : "—"}
          sub={metrics ? `${metrics.unassigned_open} unassigned` : ""}
          href="/alerts?view=unassigned"
        />
        <Tile
          label="SLA overdue"
          value={metrics ? String(metrics.sla_breached.acknowledge + metrics.sla_breached.resolve) : "—"}
          sub={metrics ? `${metrics.sla_breached.acknowledge} ack · ${metrics.sla_breached.resolve} resolve` : ""}
          alert={!!metrics && metrics.sla_breached.acknowledge + metrics.sla_breached.resolve > 0}
        />
        <Tile
          label="Verdicts"
          value={metrics ? String(decided) : "—"}
          sub={
            metrics && decided
              ? Object.entries(metrics.verdicts).map(([v, n]) => `${n} ${VERDICT_LABELS[v as Verdict]?.toLowerCase() ?? v}`).join(" · ")
              : "None recorded yet"
          }
        />
      </div>

      {metrics && (
        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <h3 className="text-xs font-semibold text-[var(--text-primary)] mb-2">Open backlog by age</h3>
            <div className="grid grid-cols-4 gap-2">
              {AGING_LABELS.map(([key, label]) => (
                <div key={key} className="p-2 rounded border border-[var(--border-color)] text-center">
                  <span className="block font-mono text-sm font-bold text-[var(--text-primary)]">{metrics.open_aging[key]}</span>
                  <span className="text-[10px] text-[var(--text-muted)]">{label}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h3 className="text-xs font-semibold text-[var(--text-primary)] mb-2">Rule precision (closed alerts)</h3>
            {metrics.rule_precision.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">Close alerts with a verdict to measure which rules are noisy.</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[10px] uppercase text-[var(--text-muted)] text-left">
                    <th className="py-1 font-semibold">Rule</th>
                    <th className="py-1 font-semibold text-right">TP</th>
                    <th className="py-1 font-semibold text-right">FP</th>
                    <th className="py-1 font-semibold text-right">Precision</th>
                  </tr>
                </thead>
                <tbody>
                  {metrics.rule_precision.slice(0, 6).map((r) => (
                    <tr key={r.rule} className="border-t border-[var(--border-color)]">
                      <td className="py-1.5 font-mono truncate max-w-[220px]" title={r.rule}>{r.rule}</td>
                      <td className="py-1.5 text-right font-mono">{r.true_positive}</td>
                      <td className="py-1.5 text-right font-mono">{r.false_positive}</td>
                      <td className={`py-1.5 text-right font-mono font-semibold ${r.precision != null && r.precision < 0.5 ? "text-[#EF4444]" : "text-[var(--text-primary)]"}`}>
                        {r.precision == null ? "—" : `${Math.round(r.precision * 100)}%`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function Tile({ label, value, sub, href, alert }: { label: string; value: string; sub?: string; href?: string; alert?: boolean }) {
  const body = (
    <>
      <span className="text-[11px] text-[var(--text-muted)] block">{label}</span>
      <span className={`font-mono text-2xl font-bold ${alert ? "text-[#EF4444]" : "text-[var(--text-primary)]"}`}>{value}</span>
      {sub && <span className="text-[10px] text-[var(--text-muted)] block truncate" title={sub}>{sub}</span>}
    </>
  );
  return href ? (
    <Link href={href} className="p-3 rounded border border-[var(--border-color)] bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] min-w-0">
      {body}
    </Link>
  ) : (
    <div className="p-3 rounded border border-[var(--border-color)] bg-[var(--surface-secondary)] min-w-0">{body}</div>
  );
}
