"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  CircleAlert,
  Download,
  FileDown,
  Loader2,
  MessageSquare,
  Play,
  History,
  Layers,
  UserCheck,
} from "lucide-react";
import ContextPanel from "@/components/investigation/ContextPanel";
import EnrichmentPanel from "@/components/investigation/EnrichmentPanel";
import InvestigationModal from "@/components/investigation/InvestigationModal";
import ProcessTreeGraph from "@/components/investigation/ProcessTreeGraph";
import DispositionDialog from "@/components/triage/DispositionDialog";
import { SeverityBadge, SlaBadge, StatusBadge } from "@/components/triage/Badges";
import { useAuth } from "@/context/AuthContext";
import { apiFetch } from "@/lib/api";
import { roleLabel } from "@/lib/roles";
import {
  ACTION_LABELS,
  MANAGER_ROLES,
  VERDICT_LABELS,
  addNote,
  allowedActions,
  fetchAudit,
  fetchNotes,
  fetchUsers,
  relativeTime,
  setAssignee,
  setDisposition,
  type AuditEntry,
  type DirectoryUser,
  type DispositionAction,
  type Note,
  type Verdict,
} from "@/lib/triage";
import { fetchIncident, type IncidentDetail } from "@/lib/incidents";
import { engineLabel, type AlertRecord } from "@/lib/types";

type Tab = "overview" | "iocs" | "tree" | "context";

const ACTION_KEYS: Record<string, DispositionAction> = { c: "close", e: "escalate", s: "suppress", r: "reopen" };

export default function AlertDetailPage() {
  const params = useParams<{ id: string }>();
  const alertId = decodeURIComponent(params.id);
  const { user } = useAuth();
  const [alert, setAlert] = useState<AlertRecord | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [dialog, setDialog] = useState<DispositionAction | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const [noteDraft, setNoteDraft] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const [downloading, setDownloading] = useState<"full" | "executive" | null>(null);
  const noteRef = useRef<HTMLTextAreaElement | null>(null);

  const isManager = !!user && MANAGER_ROLES.includes(user.role);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}`);
      if (res.status === 404) {
        setNotFound(true);
        return;
      }
      if (!res.ok) throw new Error("Unable to load alert");
      const loaded = (await res.json()) as AlertRecord;
      setAlert(loaded);
      setIncident(loaded.incident_id ? await fetchIncident(loaded.incident_id).catch(() => null) : null);
      const [n, a] = await Promise.all([fetchNotes(alertId), fetchAudit(alertId)]);
      setNotes(n);
      setAudit(a);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load alert");
    }
  }, [alertId]);

  useEffect(() => {
    const t = setTimeout(() => void load(), 0);
    fetchUsers().then(setUsers).catch(() => setUsers([]));
    return () => clearTimeout(t);
  }, [load]);

  const actions = alert ? allowedActions(alert.status) : [];

  const assign = async (assigneeId: string | null) => {
    setAssigning(true);
    try {
      await setAssignee(alertId, assigneeId);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to change assignee");
    } finally {
      setAssigning(false);
    }
  };

  // Keyboard: c/e/s/r open the matching action, n focuses the note box, a assigns to me.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (dialog || investigating || e.ctrlKey || e.metaKey || e.altKey) return;
      if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      const action = ACTION_KEYS[e.key];
      if (action && actions.includes(action)) {
        e.preventDefault();
        setDialog(action);
      } else if (e.key === "n") {
        e.preventDefault();
        noteRef.current?.focus();
      } else if (e.key === "a" && user && alert && alert.assignee_id !== user.sub) {
        e.preventDefault();
        void assign(user.sub);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const submitNote = async () => {
    if (!noteDraft.trim()) return;
    setSavingNote(true);
    try {
      await addNote(alertId, noteDraft.trim());
      setNoteDraft("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to add note");
    } finally {
      setSavingNote(false);
    }
  };

  const downloadReport = async (type: "full" | "executive") => {
    setDownloading(type);
    try {
      const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/report/${type}`);
      if (!res.ok) throw new Error("Report generation failed");
      const url = URL.createObjectURL(await res.blob());
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `forensiq_${type}_report.pdf`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed");
    } finally {
      setDownloading(null);
    }
  };

  if (notFound) {
    return (
      <div className="page-state flex-col gap-3">
        <span>Alert not found, or it belongs to another organisation.</span>
        <Link href="/alerts" className="button-secondary text-xs">Back to queue</Link>
      </div>
    );
  }
  if (!alert) {
    return (
      <div className="page-state">
        {error ? <span className="text-[#EF4444]">{error}</span> : <Loader2 className="h-5 w-5 animate-spin" />}
      </div>
    );
  }

  const canAssignOthers = isManager;
  const assigneeOptions = canAssignOthers ? users : users.filter((u) => u.id === user?.sub);

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-4 pb-12">
      <Link href="/alerts" className="inline-flex items-center gap-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] w-fit">
        <ArrowLeft className="w-3.5 h-3.5" /> Alert queue
      </Link>

      {/* Header */}
      <header className="card p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <StatusBadge alert={alert} />
          <SlaBadge alert={alert} />
          <span className="font-mono text-[10px] text-[var(--text-muted)]">{alert._id.slice(0, 12)}</span>
        </div>
        {incident && incident.alert_count > 1 && (
          <Link href={`/incidents/${encodeURIComponent(incident.id)}`} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border border-[var(--border-color)] hover:bg-[var(--surface-hover)] w-fit">
            <Layers className="w-3.5 h-3.5" />
            Part of an incident: {incident.alert_count} alerts, {incident.open_count} open · {incident.hosts.length} host{incident.hosts.length === 1 ? "" : "s"}
          </Link>
        )}
        <h1 className="text-lg font-bold text-[var(--text-primary)] break-words">
          {alert.title.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i, "")}
        </h1>
        <dl className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <Field label="Host" value={alert.host} mono />
          <Field label="User" value={alert.user} mono />
          <Field label="Rule" value={alert.rule_name} mono />
          <Field label="Detected" value={alert.detected_at ? `${relativeTime(alert.detected_at)} (${new Date(alert.detected_at).toLocaleString()})` : undefined} />
          <Field label="Event time" value={alert.created_at ? new Date(alert.created_at).toLocaleString() : undefined} />
        </dl>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border-color)] pt-3">
          <div className="flex items-center gap-2 text-xs">
            <UserCheck className="w-4 h-4 text-[var(--text-muted)]" />
            <label htmlFor="assignee" className="text-[var(--text-muted)]">Assignee</label>
            <select
              id="assignee"
              value={alert.assignee_id ?? ""}
              disabled={assigning || (!canAssignOthers && !!alert.assignee_id && alert.assignee_id !== user?.sub)}
              onChange={(e) => void assign(e.target.value || null)}
              className="field h-8 text-xs cursor-pointer min-w-[200px]"
            >
              <option value="">Unassigned</option>
              {alert.assignee_id && !assigneeOptions.some((u) => u.id === alert.assignee_id) && (
                <option value={alert.assignee_id}>{alert.assignee_email}</option>
              )}
              {assigneeOptions.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.email} ({roleLabel(u.role)})
                </option>
              ))}
            </select>
            {user && alert.assignee_id !== user.sub && (
              <button onClick={() => void assign(user.sub)} disabled={assigning} className="button-secondary text-xs" title="Shortcut: a">
                Assign to me
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {actions.map((a) => (
              <button
                key={a}
                onClick={() => setDialog(a)}
                className={a === "close" ? "button-primary text-xs" : "button-secondary text-xs"}
                title={`Shortcut: ${Object.entries(ACTION_KEYS).find(([, v]) => v === a)?.[0]}`}
              >
                {ACTION_LABELS[a]}
              </button>
            ))}
            <span className="w-px h-5 bg-[var(--border-color)] mx-1" />
            <button onClick={() => setInvestigating(true)} className="button-secondary text-xs">
              <Play className="w-3.5 h-3.5" />
              <span>{alert.risk_assessment || alert.status === "Investigated" ? "Re-run investigation" : "Run investigation"}</span>
            </button>
            <button onClick={() => void downloadReport("executive")} disabled={!!downloading} className="button-secondary text-xs" aria-label="Download executive summary PDF">
              {downloading === "executive" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}
              <span>Exec PDF</span>
            </button>
            <button onClick={() => void downloadReport("full")} disabled={!!downloading} className="button-secondary text-xs" aria-label="Download full report PDF">
              {downloading === "full" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              <span>Full PDF</span>
            </button>
          </div>
        </div>

        {(alert.status === "Closed" || alert.status === "Suppressed") && (
          <p className="text-xs text-[var(--text-secondary)] border-t border-[var(--border-color)] pt-3">
            {alert.status} by {alert.resolved_by ?? "unknown"} {relativeTime(alert.resolved_at)}
            {alert.verdict ? ` as ${VERDICT_LABELS[alert.verdict as Verdict] ?? alert.verdict}` : ""}
            {alert.disposition_note ? `: "${alert.disposition_note}"` : ""}
          </p>
        )}
      </header>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
        {/* Evidence */}
        <section className="card p-4 min-w-0">
          <div className="flex border-b border-[var(--border-color)] mb-4 overflow-x-auto" role="tablist">
            {([
              ["overview", "Assessment"],
              ["iocs", `Indicators (${alert.extracted_iocs?.length ?? 0})`],
              ["tree", "Process tree"],
              ["context", "Raw event"],
            ] as [Tab, string][]).map(([key, label]) => (
              <button
                key={key}
                role="tab"
                aria-selected={tab === key}
                onClick={() => setTab(key)}
                className={`px-3 py-2 text-xs font-semibold border-b-2 whitespace-nowrap ${
                  tab === key ? "border-[var(--text-primary)] text-[var(--text-primary)]" : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {tab === "overview" && <Assessment alert={alert} />}
          {tab === "iocs" && <EnrichmentPanel alert={alert} />}
          {tab === "tree" && <ProcessTreeGraph alert={alert} />}
          {tab === "context" && <ContextPanel alert={alert} />}
        </section>

        {/* Collaboration */}
        <aside className="flex flex-col gap-4 min-w-0">
          <section className="card p-4 space-y-3">
            <h2 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-[var(--text-muted)]" /> Notes ({notes.length})
            </h2>
            <div className="space-y-2.5 max-h-80 overflow-y-auto">
              {notes.length === 0 && <p className="text-xs text-[var(--text-muted)]">No notes yet.</p>}
              {notes.map((n) => (
                <div key={n._id} className="text-xs border border-[var(--border-color)] rounded p-2.5 bg-[var(--surface-secondary)]">
                  <div className="flex justify-between gap-2 text-[10px] text-[var(--text-muted)] mb-1">
                    <span className="truncate">{n.author_email}</span>
                    <span title={new Date(n.created_at).toLocaleString()}>{relativeTime(n.created_at)}</span>
                  </div>
                  <p className="text-[var(--text-primary)] whitespace-pre-wrap break-words">{n.content}</p>
                </div>
              ))}
            </div>
            <textarea
              ref={noteRef}
              value={noteDraft}
              onChange={(e) => setNoteDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) void submitNote();
              }}
              rows={3}
              maxLength={5000}
              placeholder="Add a note (n to focus, Ctrl+Enter to save)"
              aria-label="New note"
              className="field w-full text-xs p-2.5"
            />
            <div className="flex justify-end">
              <button onClick={() => void submitNote()} disabled={savingNote || !noteDraft.trim()} className="button-primary text-xs disabled:opacity-50">
                {savingNote && <Loader2 className="w-3.5 h-3.5 animate-spin" />} Add note
              </button>
            </div>
          </section>

          <section className="card p-4 space-y-3">
            <h2 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
              <History className="w-4 h-4 text-[var(--text-muted)]" /> Activity
            </h2>
            {audit.length === 0 && <p className="text-xs text-[var(--text-muted)]">No analyst activity yet.</p>}
            <ol className="space-y-2.5 max-h-96 overflow-y-auto">
              {audit.map((a) => (
                <li key={a._id} className="text-xs border-l-2 border-[var(--border-color)] pl-2.5">
                  <div className="text-[var(--text-primary)]">{describeAudit(a)}</div>
                  <div className="text-[10px] text-[var(--text-muted)]">
                    {a.actor_email} · <span title={new Date(a.created_at).toLocaleString()}>{relativeTime(a.created_at)}</span>
                  </div>
                  {a.metadata?.note && <p className="text-[var(--text-secondary)] mt-0.5 italic break-words">&ldquo;{a.metadata.note}&rdquo;</p>}
                </li>
              ))}
            </ol>
          </section>
        </aside>
      </div>

      {dialog && (
        <DispositionDialog
          action={dialog}
          count={1}
          severity={alert.severity}
          status={alert.status}
          role={user?.role}
          onCancel={() => setDialog(null)}
          onConfirm={async ({ note, verdict }) => {
            await setDisposition(alertId, dialog, note, verdict);
            setDialog(null);
            await load();
          }}
        />
      )}

      {investigating && (
        <InvestigationModal
          alert={alert}
          isOpen={investigating}
          onClose={() => setInvestigating(false)}
          onComplete={() => void load()}
        />
      )}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-[var(--text-muted)]">{label}</dt>
      <dd className={`text-[var(--text-primary)] truncate ${mono ? "font-mono" : ""}`} title={value ?? undefined}>{value || "—"}</dd>
    </div>
  );
}

function Assessment({ alert }: { alert: AlertRecord }) {
  const ra = alert.risk_assessment;
  if (!alert.recommendation && alert.risk_score == null) {
    return <p className="text-xs text-[var(--text-muted)]">Not investigated yet. Run the investigation to enrich indicators and get a recommendation.</p>;
  }
  return (
    <div className="space-y-4 text-xs">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Risk" value={alert.risk_score != null ? `${alert.risk_score}/100` : "—"} />
        <Stat label="Priority" value={alert.priority ?? "—"} />
        <Stat label="Confidence" value={alert.ai_confidence != null ? `${alert.ai_confidence}%` : "—"} />
        <Stat label="Assessed by" value={engineLabel(alert.engines?.risk)} />
      </div>
      {alert.unavailable_feeds && alert.unavailable_feeds.length > 0 && (
        <p className="text-[#F59E0B]">No threat-intel verdict from: {alert.unavailable_feeds.join(", ")}. Indicators were not checked against these feeds.</p>
      )}
      {ra?.reasoning && (
        <div>
          <h3 className="font-semibold text-[var(--text-primary)] mb-1">Why this score</h3>
          <p className="text-[var(--text-secondary)]">{ra.reasoning}</p>
        </div>
      )}
      {alert.recommendation && (
        <div className="p-3.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
          <h3 className="font-semibold text-[var(--text-primary)] mb-1">
            Recommended response <span className="font-normal text-[var(--text-muted)]">({engineLabel(alert.engines?.recommendation)}; suggestions, verify before acting)</span>
          </h3>
          <p className="whitespace-pre-wrap text-[var(--text-primary)]">{alert.recommendation}</p>
        </div>
      )}
      {alert.command_line && (
        <div>
          <h3 className="font-semibold text-[var(--text-primary)] mb-1">Command line</h3>
          <pre className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] font-mono text-[11px] whitespace-pre-wrap break-all">{alert.command_line}</pre>
        </div>
      )}
      {(alert.mitre_mappings ?? []).length > 0 && (
        <div>
          <h3 className="font-semibold text-[var(--text-primary)] mb-1">MITRE ATT&CK</h3>
          <ul className="flex flex-wrap gap-2">
            {(alert.mitre_mappings ?? []).map((m, i) => (
              <li key={`${m.technique}-${i}`} className="px-2 py-1 rounded border border-[var(--border-color)] font-mono text-[11px]">
                {m.technique} {m.tactic ? `· ${m.tactic}` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
      <span className="text-[11px] text-[var(--text-muted)] block">{label}</span>
      <span className="font-mono font-semibold text-[var(--text-primary)] capitalize">{value}</span>
    </div>
  );
}

function describeAudit(a: AuditEntry): string {
  const m = a.metadata ?? {};
  switch (a.action) {
    case "alert.close":
      return `Closed${m.verdict ? ` as ${VERDICT_LABELS[m.verdict as Verdict] ?? m.verdict}` : ""}`;
    case "alert.escalate":
      return "Escalated";
    case "alert.suppress":
      return "Suppressed";
    case "alert.reopen":
      return `Reopened (was ${m.from})`;
    case "alert.assigned":
      return `Assigned to ${m.to}${m.from ? ` (was ${m.from})` : ""}`;
    case "alert.unassigned":
      return `Unassigned${m.from ? ` from ${m.from}` : ""}`;
    case "alert.note_added":
      return "Added a note";
    default:
      return a.action;
  }
}
