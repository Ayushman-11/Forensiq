"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, CircleAlert, Loader2 } from "lucide-react";
import DispositionDialog from "@/components/triage/DispositionDialog";
import { SeverityBadge, SlaBadge, StatusBadge } from "@/components/triage/Badges";
import { useAuth } from "@/context/AuthContext";
import { describeKey, fetchIncident, type IncidentDetail } from "@/lib/incidents";
import { OPEN_STATUSES, bulkAction, relativeTime, type BulkResult, type DispositionAction } from "@/lib/triage";
import type { AlertRecord } from "@/lib/types";

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const incidentId = decodeURIComponent(params.id);
  const { user } = useAuth();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<DispositionAction | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchIncident(incidentId);
      if (!data) {
        setNotFound(true);
        return;
      }
      setIncident(data);
      setSelected((prev) => new Set([...prev].filter((id) => data.alerts.some((a) => a._id === id && OPEN_STATUSES.includes(a.status)))));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load incident");
    }
  }, [incidentId]);

  useEffect(() => {
    const t = setTimeout(() => void load(), 0);
    return () => clearTimeout(t);
  }, [load]);

  const run = async (fn: () => Promise<BulkResult>) => {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fn();
      const failures = res.results.filter((r) => !r.ok);
      const reasons = [...new Set(failures.map((f) => f.error))].join("; ");
      setMessage(`${res.succeeded} updated${res.failed ? `, ${res.failed} not changed: ${reasons}` : ""}`);
      setSelected(new Set(failures.map((f) => f.alert_id)));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  if (notFound) {
    return (
      <div className="page-state flex-col gap-3">
        <span>Incident not found. It may have been regrouped.</span>
        <Link href="/incidents" className="button-secondary text-xs">Back to incidents</Link>
      </div>
    );
  }
  if (!incident) {
    return <div className="page-state">{error ? <span className="text-[#EF4444]">{error}</span> : <Loader2 className="h-5 w-5 animate-spin" />}</div>;
  }

  const openAlerts = incident.alerts.filter((a) => OPEN_STATUSES.includes(a.status));
  const allOpenSelected = openAlerts.length > 0 && openAlerts.every((a) => selected.has(a._id));
  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const picked = incident.alerts.filter((a) => selected.has(a._id));
  const sharedSeverity = new Set(picked.map((a) => a.severity)).size === 1 ? picked[0]?.severity : undefined;

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-4 pb-12">
      <Link href="/incidents" className="inline-flex items-center gap-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] w-fit">
        <ArrowLeft className="w-3.5 h-3.5" /> Incidents
      </Link>

      <header className="card p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={incident.severity} />
          <span className="font-mono text-[10px] uppercase font-semibold px-2 py-0.5 rounded border border-[var(--border-color)] text-[var(--text-secondary)]">{incident.state}</span>
          <span className="font-mono text-[10px] text-[var(--text-muted)]">
            {incident.open_count} open / {incident.alert_count} alerts · active {relativeTime(incident.last_seen)}
          </span>
        </div>
        <h1 className="text-lg font-bold text-[var(--text-primary)] break-words">{incident.title}</h1>
        <dl className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <Facet label={`Hosts (${incident.hosts.length})`} values={incident.hosts} />
          <Facet label={`Accounts (${incident.users.length})`} values={incident.users} />
          <Facet label="Detections" values={incident.rules} />
        </dl>
        <div className="border-t border-[var(--border-color)] pt-3">
          <h2 className="text-[11px] font-semibold text-[var(--text-muted)] mb-1.5">Why these alerts are grouped</h2>
          <ul className="flex flex-wrap gap-1.5">
            {incident.link_keys.map((k) => (
              <li key={k} className="px-2 py-1 rounded border border-[var(--border-color)] text-[11px] font-mono break-all">{describeKey(k)}</li>
            ))}
          </ul>
        </div>
      </header>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <section className="card p-2.5 flex flex-wrap items-center gap-2 text-xs" aria-label="Incident actions">
        <button
          onClick={() => setSelected(allOpenSelected ? new Set() : new Set(openAlerts.map((a) => a._id)))}
          disabled={openAlerts.length === 0}
          className="button-secondary text-xs"
        >
          {allOpenSelected ? "Clear selection" : `Select all open (${openAlerts.length})`}
        </button>
        {selected.size > 0 && (
          <>
            <span className="font-semibold text-[var(--text-primary)]">{selected.size} selected</span>
            {user && (
              <button disabled={busy} onClick={() => void run(() => bulkAction([...selected], "assign", { assigneeId: user.sub }))} className="button-secondary text-xs">
                Assign to me
              </button>
            )}
            <button disabled={busy} onClick={() => setDialog("close")} className="button-primary text-xs">Close…</button>
            <button disabled={busy} onClick={() => setDialog("escalate")} className="button-secondary text-xs">Escalate…</button>
            <button disabled={busy} onClick={() => setDialog("suppress")} className="button-secondary text-xs">Suppress…</button>
            {busy && <Loader2 className="w-4 h-4 animate-spin" />}
          </>
        )}
        {message && <span className="text-[var(--text-secondary)] ml-auto">{message}</span>}
      </section>

      <section className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[860px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--surface-secondary)] text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                <th className="py-2.5 pl-4 w-8" />
                <th className="py-2.5 px-3 w-24">Severity</th>
                <th className="py-2.5 px-3">Alert (in time order)</th>
                <th className="py-2.5 px-3 w-32">Host</th>
                <th className="py-2.5 px-3 w-36">Assignee</th>
                <th className="py-2.5 px-3 w-28">SLA</th>
                <th className="py-2.5 px-3 w-40">Status</th>
                <th className="py-2.5 px-3 w-24">When</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-color)] text-xs">
              {incident.alerts.map((a) => {
                const open = OPEN_STATUSES.includes(a.status);
                const detail = a.dns_query || a.command_line;
                return (
                  <tr key={a._id} className={selected.has(a._id) ? "bg-[var(--sidebar-active-bg)]" : "hover:bg-[var(--surface-hover)]"}>
                    <td className="py-3 pl-4">
                      <input type="checkbox" disabled={!open} checked={selected.has(a._id)} onChange={() => toggle(a._id)} aria-label={`Select ${a.title}`} />
                    </td>
                    <td className="py-3 px-3"><SeverityBadge severity={a.severity} /></td>
                    <td className="py-3 px-3 max-w-0">
                      <Link href={`/alerts/${encodeURIComponent(a._id)}`} className="font-semibold text-[var(--text-primary)] block truncate hover:underline">
                        {a.title.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i, "")}
                      </Link>
                      <span className="block truncate font-mono text-[10px] text-[var(--text-muted)]" title={detail}>
                        {a.rule_name}{detail ? ` · ${detail}` : ""}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-[var(--text-secondary)] truncate">{a.host || "—"}</td>
                    <td className="py-3 px-3 truncate text-[var(--text-secondary)]">
                      {a.assignee_email ? (a.assignee_id === user?.sub ? "You" : a.assignee_email) : <span className="text-[var(--text-muted)]">Unassigned</span>}
                    </td>
                    <td className="py-3 px-3"><SlaBadge alert={a as unknown as AlertRecord} /></td>
                    <td className="py-3 px-3"><StatusBadge alert={a} /></td>
                    <td className="py-3 px-3 font-mono text-[var(--text-muted)] whitespace-nowrap" title={a.first_seen ? new Date(a.first_seen).toLocaleString() : undefined}>
                      {relativeTime(a.first_seen)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {dialog && (
        <DispositionDialog
          action={dialog}
          count={selected.size}
          severity={sharedSeverity}
          role={user?.role}
          onCancel={() => setDialog(null)}
          onConfirm={async ({ note, verdict }) => {
            const action = dialog;
            setDialog(null);
            await run(() => bulkAction([...selected], action, { note, verdict }));
          }}
        />
      )}
    </div>
  );
}

function Facet({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-[var(--text-muted)]">{label}</dt>
      <dd className="font-mono text-[var(--text-primary)] break-words">{values.length ? values.join(", ") : "—"}</dd>
    </div>
  );
}
