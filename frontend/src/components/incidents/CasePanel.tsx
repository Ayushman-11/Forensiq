"use client";

import { useCallback, useEffect, useState } from "react";
import { ExternalLink, Loader2, RefreshCw, Trash2 } from "lucide-react";
import {
  CASE_STATUSES,
  CASE_STATUS_LABELS,
  addIncidentNote,
  describeTimelineEntry,
  fetchIncidentNotes,
  fetchIncidentTimeline,
  fetchIncidents,
  linkTicket,
  mergeIncidents,
  pinAlert,
  setCaseOwner,
  setCaseStatus,
  splitIncident,
  syncTicket,
  unlinkTicket,
  type CaseStatus,
  type IncidentDetail,
  type IncidentNote,
  type IncidentSummary,
  type TicketSystem,
  type TimelineEntry,
} from "@/lib/incidents";
import { MANAGER_ROLES, fetchUsers, relativeTime, type DirectoryUser } from "@/lib/triage";

type Props = {
  incident: IncidentDetail;
  user: { sub: string; role?: string } | null;
  /** Alerts ticked in the table below; used by "Split off selected". */
  selectedAlertIds: string[];
  onChanged: () => Promise<void> | void;
  onSplit: (newIncidentId: string) => void;
};

const SYNC_LABEL: Record<string, string> = { ok: "Synced", error: "Sync failed", not_configured: "Not connected" };

export default function CasePanel({ incident, user, selectedAlertIds, onChanged, onSplit }: Props) {
  const [tab, setTab] = useState<"notes" | "timeline">("notes");
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [noteText, setNoteText] = useState("");
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [openIncidents, setOpenIncidents] = useState<IncidentSummary[]>([]);
  const [status, setStatus] = useState<CaseStatus>(incident.status);
  const [statusNote, setStatusNote] = useState("");
  const [ticketSystem, setTicketSystem] = useState<TicketSystem>("jira");
  const [ticketKey, setTicketKey] = useState("");
  const [mergeId, setMergeId] = useState("");
  const [reason, setReason] = useState("");
  const [pinId, setPinId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const isManager = !!user?.role && MANAGER_ROLES.includes(user.role);
  const closing = status === "resolved" || status === "closed";

  const refresh = useCallback(async () => {
    try {
      const [n, t] = await Promise.all([fetchIncidentNotes(incident.id), fetchIncidentTimeline(incident.id)]);
      setNotes(n);
      setTimeline(t);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load case history");
    }
  }, [incident.id]);

  useEffect(() => {
    const t = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(t);
  }, [refresh, incident.status, incident.case_owner, incident.alert_count]);

  useEffect(() => {
    const t = setTimeout(() => {
      fetchUsers().then(setUsers).catch(() => setUsers([]));
      fetchIncidents("open").then((rows) => setOpenIncidents(rows.filter((r) => r.id !== incident.id))).catch(() => setOpenIncidents([]));
    }, 0);
    return () => clearTimeout(t);
  }, [incident.id]);

  useEffect(() => {
    const t = setTimeout(() => setStatus(incident.status), 0);
    return () => clearTimeout(t);
  }, [incident.status]);

  const act = async (fn: () => Promise<unknown>, success?: string) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await fn();
      if (success) setInfo(success);
      await onChanged();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const applyStatus = (force = false) =>
    act(async () => {
      await setCaseStatus(incident.id, status, statusNote.trim() || undefined, force);
      setStatusNote("");
    }, "Status updated");

  return (
    <section className="card p-4 space-y-4" aria-label="Case management">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2">
          <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">Case status</h2>
          <div className="flex flex-wrap items-center gap-2">
            <select value={status} onChange={(e) => setStatus(e.target.value as CaseStatus)} className="field h-8 text-xs cursor-pointer" aria-label="Case status">
              {CASE_STATUSES.map((s) => (
                <option key={s} value={s}>{CASE_STATUS_LABELS[s]}</option>
              ))}
            </select>
            <button className="button-primary text-xs" disabled={busy || status === incident.status || (closing && !statusNote.trim())} onClick={() => void applyStatus()}>
              Update
            </button>
            {isManager && closing && incident.open_count > 0 && (
              <button className="button-secondary text-xs" disabled={busy || !statusNote.trim()} onClick={() => void applyStatus(true)} title="Resolve even though member alerts are still open">
                Force
              </button>
            )}
          </div>
          {closing && status !== incident.status && (
            <textarea value={statusNote} onChange={(e) => setStatusNote(e.target.value)} placeholder="Resolution note (required)" rows={2} className="field w-full text-xs" aria-label="Resolution note" />
          )}
          {incident.resolution_note && <p className="text-xs text-[var(--text-secondary)]">Resolution: {incident.resolution_note}</p>}
        </div>

        <div className="space-y-2">
          <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">Owner</h2>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-[var(--text-primary)]">{incident.case_owner ? (incident.case_owner_id === user?.sub ? "You" : incident.case_owner) : "Nobody"}</span>
            {user && incident.case_owner_id !== user.sub && (
              <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(() => setCaseOwner(incident.id, user.sub), "You own this case")}>Take ownership</button>
            )}
            {incident.case_owner_id && (isManager || incident.case_owner_id === user?.sub) && (
              <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(() => setCaseOwner(incident.id, null), "Released")}>Release</button>
            )}
            {isManager && users.length > 0 && (
              <select
                value=""
                onChange={(e) => e.target.value && void act(() => setCaseOwner(incident.id, e.target.value), "Owner changed")}
                className="field h-8 text-xs cursor-pointer"
                aria-label="Assign owner"
              >
                <option value="">Assign to…</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>{u.email}</option>
                ))}
              </select>
            )}
          </div>
        </div>
      </div>

      {(error || info) && (
        <p role={error ? "alert" : "status"} className={`text-xs ${error ? "text-[#EF4444]" : "text-[var(--text-secondary)]"}`}>{error ?? info}</p>
      )}

      <div className="grid gap-4 md:grid-cols-2 border-t border-[var(--border-color)] pt-4">
        <div className="space-y-2">
          <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">External tickets</h2>
          {incident.tickets.length === 0 && <p className="text-xs text-[var(--text-muted)]">No tickets linked.</p>}
          <ul className="space-y-1.5">
            {incident.tickets.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center gap-2 text-xs border border-[var(--border-color)] rounded px-2 py-1.5">
                <span className="font-mono font-semibold">{t.key}</span>
                <span className="text-[var(--text-muted)]">{t.system}</span>
                <span className="text-[var(--text-secondary)]">{t.external_status}</span>
                <span className={t.sync_state === "error" ? "text-[#EF4444]" : "text-[var(--text-muted)]"} title={t.sync_error ?? undefined}>
                  {SYNC_LABEL[t.sync_state] ?? t.sync_state}{t.last_synced_at ? ` ${relativeTime(t.last_synced_at)}` : ""}
                </span>
                <span className="ml-auto flex items-center gap-1.5">
                  {t.url && (
                    <a href={t.url} target="_blank" rel="noopener noreferrer" aria-label={`Open ${t.key}`} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                  <button disabled={busy || t.sync_state === "not_configured"} aria-label={`Sync ${t.key}`} title="Pull the ticket's status" onClick={() => void act(async () => {
                    const r = await syncTicket(incident.id, t.id);
                    setInfo(r.applied_status ? `Incident status followed the ticket: ${CASE_STATUS_LABELS[r.applied_status]}` : "Ticket status refreshed");
                  })}>
                    <RefreshCw className="h-3.5 w-3.5" />
                  </button>
                  <button disabled={busy} aria-label={`Unlink ${t.key}`} onClick={() => void act(() => unlinkTicket(incident.id, t.id), "Ticket unlinked")}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </span>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center gap-2">
            <select value={ticketSystem} onChange={(e) => setTicketSystem(e.target.value as TicketSystem)} className="field h-8 text-xs cursor-pointer" aria-label="Ticket system">
              <option value="jira">Jira</option>
              <option value="servicenow">ServiceNow</option>
            </select>
            <input value={ticketKey} onChange={(e) => setTicketKey(e.target.value)} placeholder={ticketSystem === "jira" ? "SEC-123" : "INC0012345"} className="field h-8 text-xs w-32 font-mono" aria-label="Ticket key" />
            <button className="button-secondary text-xs" disabled={busy || !ticketKey.trim()} onClick={() => void act(async () => { await linkTicket(incident.id, ticketSystem, ticketKey.trim()); setTicketKey(""); }, "Ticket linked")}>Link</button>
            <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(() => linkTicket(incident.id, ticketSystem, undefined, true), "Ticket created")}>Create new</button>
          </div>
        </div>

        <div className="space-y-2">
          <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">Merge and split</h2>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (required for merge or split)" className="field h-8 text-xs w-full" aria-label="Reason" />
          <div className="flex flex-wrap items-center gap-2">
            <select value={mergeId} onChange={(e) => setMergeId(e.target.value)} className="field h-8 text-xs cursor-pointer max-w-[16rem]" aria-label="Incident to merge in">
              <option value="">Merge another incident in…</option>
              {openIncidents.map((o) => (
                <option key={o.id} value={o.id}>{o.title.slice(0, 60)} ({o.alert_count})</option>
              ))}
            </select>
            <button className="button-secondary text-xs" disabled={busy || !mergeId || !reason.trim()} onClick={() => void act(async () => { await mergeIncidents(incident.id, [mergeId], reason.trim()); setMergeId(""); setReason(""); }, "Incidents merged")}>Merge</button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              className="button-secondary text-xs"
              disabled={busy || selectedAlertIds.length === 0 || !reason.trim()}
              title="Tick alerts in the table first"
              onClick={() => void act(async () => {
                const r = await splitIncident(incident.id, selectedAlertIds, reason.trim());
                setReason("");
                onSplit(r.new_incident_id);
              })}
            >
              Split off selected ({selectedAlertIds.length})
            </button>
            <span className="text-[11px] text-[var(--text-muted)]">Moved alerts stay in their new incident when incidents are regrouped.</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input value={pinId} onChange={(e) => setPinId(e.target.value)} placeholder="Alert ID to pin here" className="field h-8 text-xs w-56 font-mono" aria-label="Alert ID to pin" />
            <button className="button-secondary text-xs" disabled={busy || !pinId.trim()} onClick={() => void act(async () => { await pinAlert(incident.id, pinId.trim()); setPinId(""); }, "Alert pinned to this incident")}>Pin alert</button>
          </div>
        </div>
      </div>

      <div className="border-t border-[var(--border-color)] pt-4 space-y-2">
        <div className="flex gap-1 text-xs" role="tablist">
          {(["notes", "timeline"] as const).map((k) => (
            <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)} className={tab === k ? "button-primary text-xs" : "button-secondary text-xs"}>
              {k === "notes" ? `Notes (${notes.length})` : `Timeline (${timeline.length})`}
            </button>
          ))}
          {busy && <Loader2 className="ml-2 h-4 w-4 animate-spin self-center" />}
        </div>

        {tab === "notes" ? (
          <div className="space-y-2">
            <div className="flex gap-2">
              <textarea value={noteText} onChange={(e) => setNoteText(e.target.value)} placeholder="Add a note for the whole incident" rows={2} className="field flex-1 text-xs" aria-label="New note" />
              <button className="button-primary text-xs self-start" disabled={busy || !noteText.trim()} onClick={() => void act(async () => { await addIncidentNote(incident.id, noteText.trim()); setNoteText(""); })}>Add</button>
            </div>
            <ul className="space-y-2 text-xs">
              {notes.map((n) => (
                <li key={n._id} className="border border-[var(--border-color)] rounded px-3 py-2">
                  <p className="whitespace-pre-wrap break-words text-[var(--text-primary)]">{n.content}</p>
                  <p className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">{n.author_email} · {relativeTime(n.created_at)}</p>
                </li>
              ))}
              {notes.length === 0 && <li className="text-[var(--text-muted)]">No notes yet.</li>}
            </ul>
          </div>
        ) : (
          <ol className="space-y-1.5 text-xs">
            {timeline.map((e, i) => (
              <li key={`${e.type}-${e.at}-${i}`} className="flex gap-3">
                <span className="w-20 shrink-0 font-mono text-[10px] text-[var(--text-muted)]" title={new Date(e.at).toLocaleString()}>{relativeTime(e.at)}</span>
                <span className="text-[var(--text-primary)] break-words">{describeTimelineEntry(e)}{e.actor ? <span className="text-[var(--text-muted)]"> · {e.actor}</span> : null}</span>
              </li>
            ))}
            {timeline.length === 0 && <li className="text-[var(--text-muted)]">Nothing recorded yet.</li>}
          </ol>
        )}
      </div>
    </section>
  );
}
