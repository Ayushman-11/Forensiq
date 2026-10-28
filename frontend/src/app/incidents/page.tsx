"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { CircleAlert, Loader2, RefreshCw, Shuffle } from "lucide-react";
import { SeverityBadge } from "@/components/triage/Badges";
import { useAuth } from "@/context/AuthContext";
import { fetchIncidents, rebuildIncidents, type IncidentSummary } from "@/lib/incidents";
import { MANAGER_ROLES, relativeTime } from "@/lib/triage";

const TABS = [
  { key: "open", label: "Open" },
  { key: "resolved", label: "Resolved" },
  { key: "all", label: "All" },
] as const;

export default function IncidentsPage() {
  const { user } = useAuth();
  const isManager = !!user && MANAGER_ROLES.includes(user.role);
  const [tab, setTab] = useState<(typeof TABS)[number]["key"]>("open");
  const [rows, setRows] = useState<IncidentSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rebuilding, setRebuilding] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      setRows(await fetchIncidents(tab));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load incidents");
    }
  }, [tab]);

  useEffect(() => {
    const t = setTimeout(() => void load(), 0);
    return () => clearTimeout(t);
  }, [load]);

  const rebuild = async () => {
    if (!window.confirm("Regroup every alert into incidents? Existing groupings are recomputed; alert statuses, notes and assignments are not touched.")) return;
    setRebuilding(true);
    setMessage(null);
    try {
      const r = await rebuildIncidents();
      setMessage(`Regrouped ${r.linked} of ${r.alerts} alerts into ${r.incidents} incidents.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Regrouping failed");
    } finally {
      setRebuilding(false);
    }
  };

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-4 pb-12">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">Incidents</h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Related alerts grouped by host, account, file hash or domain within a few hours. Work the case, not each alert.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isManager && (
            <button onClick={() => void rebuild()} disabled={rebuilding} className="button-secondary text-xs" title="Recompute all groupings">
              {rebuilding ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Shuffle className="h-3.5 w-3.5" />}
              <span>Regroup</span>
            </button>
          )}
          <button onClick={() => void load()} className="button-secondary text-xs">
            <RefreshCw className="h-3.5 w-3.5" /> <span>Refresh</span>
          </button>
        </div>
      </header>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {message && <p className="text-xs text-[var(--text-secondary)]">{message}</p>}

      <nav className="flex gap-1" aria-label="Incident state">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            aria-current={tab === t.key ? "page" : undefined}
            className={`px-3 py-1.5 rounded text-xs font-medium border ${
              tab === t.key ? "bg-[var(--surface-primary)] border-[var(--text-primary)] text-[var(--text-primary)]" : "border-[var(--border-color)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <section className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[860px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--surface-secondary)] text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                <th className="py-2.5 px-4 w-24">Severity</th>
                <th className="py-2.5 px-3">Incident</th>
                <th className="py-2.5 px-3 w-28">Alerts</th>
                <th className="py-2.5 px-3 w-44">Owner</th>
                <th className="py-2.5 px-3 w-40">Span</th>
                <th className="py-2.5 px-3 w-28">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-color)] text-xs">
              {rows === null ? (
                <tr><td colSpan={6} className="py-12 text-center text-[var(--text-muted)]"><Loader2 className="w-5 h-5 animate-spin mx-auto" /></td></tr>
              ) : rows.length === 0 ? (
                <tr><td colSpan={6} className="py-12 text-center text-[var(--text-muted)]">
                  {tab === "open" ? "No open incidents." : "No incidents here."}{isManager && tab === "open" ? " If alerts exist but no incidents do, use Regroup." : ""}
                </td></tr>
              ) : (
                rows.map((r) => (
                  <tr key={r.id} className="hover:bg-[var(--surface-hover)]">
                    <td className="py-3 px-4"><SeverityBadge severity={r.severity} /></td>
                    <td className="py-3 px-3 max-w-0">
                      <Link href={`/incidents/${encodeURIComponent(r.id)}`} className="font-semibold text-[var(--text-primary)] block truncate hover:underline">
                        {r.title}
                      </Link>
                      <span className="block truncate font-mono text-[10px] text-[var(--text-muted)]" title={r.users.join(", ")}>
                        {r.hosts.length} host{r.hosts.length === 1 ? "" : "s"}{r.users.length ? ` · ${r.users.slice(0, 2).join(", ")}` : ""}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      {r.open_count}
                      <span className="text-[var(--text-muted)]"> open / {r.alert_count}</span>
                    </td>
                    <td className="py-3 px-3 truncate">
                      {r.state === "resolved" ? <span className="text-[var(--text-muted)]">—</span>
                        : r.owner ? (r.owner === user?.email ? "You" : r.owner)
                        : r.mixed_owners ? <span className="text-[var(--text-muted)]">Several ({r.unassigned_open} unassigned)</span>
                        : <span className="text-[var(--text-muted)]">Unassigned</span>}
                    </td>
                    <td className="py-3 px-3 font-mono text-[var(--text-muted)] whitespace-nowrap" title={r.first_seen ? new Date(r.first_seen).toLocaleString() : undefined}>
                      {relativeTime(r.last_seen)}
                    </td>
                    <td className="py-3 px-3">
                      <span className="font-mono text-[10px] uppercase font-semibold px-2 py-0.5 rounded border border-[var(--border-color)] bg-[var(--surface-elevated)] text-[var(--text-secondary)]">
                        {r.state}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
