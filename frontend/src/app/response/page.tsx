"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { CircleAlert, Loader2, ShieldOff } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { MANAGER_ROLES, relativeTime } from "@/lib/triage";
import {
  STATUS_LABELS,
  approveRequest,
  cancelRequest,
  createRequest,
  dryRunRequest,
  executeRequest,
  fetchCapabilities,
  fetchResponseRequests,
  rejectRequest,
  rollbackRequest,
  type Capabilities,
  type ResponseRequest,
} from "@/lib/response";

const TARGET_HINT: Record<string, string> = { host: "Hostname or device id", user: "user@corp.com or Okta id", ip: "IPv4 or IPv6 address" };

function ResponseView() {
  const { user } = useAuth();
  const params = useSearchParams();
  const isManager = !!user && MANAGER_ROLES.includes(user.role);
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [rows, setRows] = useState<ResponseRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionType, setActionType] = useState("edr.isolate_host");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [creating, setCreating] = useState(false);
  const incidentId = params.get("incident") ?? undefined;
  const alertId = params.get("alert") ?? undefined;

  const load = useCallback(async () => {
    try {
      const [c, r] = await Promise.all([fetchCapabilities(), fetchResponseRequests()]);
      setCaps(c);
      setRows(r);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load response actions");
    }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => void load(), 0);
    return () => clearTimeout(t);
  }, [load]);

  const run = async (id: string, fn: () => Promise<unknown>) => {
    setBusyId(id);
    setError(null);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
      await load();
    } finally {
      setBusyId(null);
    }
  };

  const ask = (prompt: string): string | null => {
    const value = window.prompt(prompt);
    return value && value.trim() ? value.trim() : null;
  };

  const submit = async () => {
    setCreating(true);
    setError(null);
    try {
      await createRequest({ action_type: actionType, target: target.trim(), reason: reason.trim(), incident_id: incidentId, alert_id: alertId });
      setTarget("");
      setReason("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to create request");
    } finally {
      setCreating(false);
    }
  };

  const spec = caps?.actions[actionType];

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-4 pb-12">
      <header className="border-b border-[var(--border-color)] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">Response actions</h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Contain hosts, disable accounts and block addresses. Every request needs approval from a different SOC manager, and every step is audited.
        </p>
      </header>

      {caps && !caps.live_execution_enabled && (
        <div className="feedback-error" role="status">
          <ShieldOff className="h-4 w-4 shrink-0" />
          <span>Live execution is switched off on this server. You can request, approve and dry-run, but nothing will change on a target system.</span>
        </div>
      )}
      {error && (
        <div className="feedback-error" role="alert">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <section className="card p-4 space-y-3" aria-label="New request">
        <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
          New request{incidentId ? ` for incident ${incidentId.slice(0, 8)}` : ""}
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <select value={actionType} onChange={(e) => setActionType(e.target.value)} className="field h-8 text-xs cursor-pointer" aria-label="Action">
            {caps && Object.entries(caps.actions).map(([key, a]) => (
              <option key={key} value={key}>{a.label}{a.configured ? "" : " (not connected)"}</option>
            ))}
          </select>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={spec ? TARGET_HINT[spec.target] : "Target"} className="field h-8 text-xs w-72 font-mono" aria-label="Target" />
        </div>
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="Why? (at least 10 characters; approvers read this)" className="field w-full text-xs" aria-label="Reason" />
        {spec && !spec.configured && <p className="text-xs text-[var(--text-muted)]">The {spec.connector} connector is not configured, so the target cannot be checked or actioned yet.</p>}
        <button className="button-primary text-xs" disabled={creating || !target.trim() || reason.trim().length < 10} onClick={() => void submit()}>
          {creating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Request approval"}
        </button>
      </section>

      <section className="space-y-3" aria-label="Requests">
        {rows === null && !error && <div className="page-state"><Loader2 className="h-5 w-5 animate-spin" /></div>}
        {rows?.length === 0 && <p className="text-sm text-[var(--text-muted)]">No response requests yet.</p>}
        {rows?.map((r) => {
          const own = r.requested_by.id === user?.sub;
          const busy = busyId === r.id;
          const canRun = isManager || own;
          return (
            <article key={r.id} className="card p-4 space-y-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-sm text-[var(--text-primary)]">{r.action_label}</span>
                <span className="font-mono">{r.target}</span>
                <span className="font-mono text-[10px] uppercase font-semibold px-2 py-0.5 rounded border border-[var(--border-color)]">{STATUS_LABELS[r.status]}</span>
                <span className="ml-auto text-[var(--text-muted)]">{r.requested_by.email} · {relativeTime(r.requested_at)}</span>
              </div>
              <p className="text-[var(--text-secondary)] whitespace-pre-wrap break-words">{r.reason}</p>
              <p className="text-[var(--text-muted)]">
                Preview: {r.preview.summary}
                {r.preview.details && "note" in r.preview.details && r.preview.details.note ? ` (${String(r.preview.details.note)})` : ""}
              </p>
              {r.approval && <p className="text-[var(--text-muted)]">Approved by {r.approval.by.email}{r.status === "approved" ? `, valid until ${new Date(r.approval.expires_at).toLocaleTimeString()}` : ""}{r.approval.note ? `: ${r.approval.note}` : ""}</p>}
              {r.rejection && <p className="text-[var(--text-muted)]">Rejected by {r.rejection.by.email}: {r.rejection.note}</p>}
              {r.executions.length > 0 && (
                <ul className="space-y-0.5 border-t border-[var(--border-color)] pt-2">
                  {r.executions.map((e, i) => (
                    <li key={i} className={e.ok ? "text-[var(--text-secondary)]" : "text-[#EF4444]"}>
                      <span className="font-mono uppercase text-[10px] mr-2">{e.kind.replace("_", " ")}</span>{e.summary}
                      <span className="text-[var(--text-muted)]"> · {e.by} · {relativeTime(e.at)}</span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                {["pending_approval", "approved", "failed", "succeeded"].includes(r.status) && canRun && (
                  <button className="button-secondary text-xs" disabled={busy} onClick={() => void run(r.id, () => dryRunRequest(r.id))}>Dry run</button>
                )}
                {r.status === "pending_approval" && isManager && !own && (
                  <>
                    <button className="button-primary text-xs" disabled={busy} onClick={() => void run(r.id, () => approveRequest(r.id))}>Approve</button>
                    <button className="button-secondary text-xs" disabled={busy} onClick={() => { const n = ask("Why is this rejected?"); if (n) void run(r.id, () => rejectRequest(r.id, n)); }}>Reject</button>
                  </>
                )}
                {r.status === "pending_approval" && isManager && own && <span className="text-[var(--text-muted)]">Another manager must approve your request.</span>}
                {(r.status === "approved" || r.status === "failed") && canRun && (
                  <button className="button-primary text-xs" disabled={busy || !caps?.live_execution_enabled} title={caps?.live_execution_enabled ? undefined : "Live execution is switched off on this server"}
                    onClick={() => { if (window.confirm(`${r.action_label} on ${r.target}? This changes the target system now.`)) void run(r.id, () => executeRequest(r.id)); }}>
                    Execute
                  </button>
                )}
                {r.status === "succeeded" && isManager && (
                  <button className="button-secondary text-xs" disabled={busy || !caps?.live_execution_enabled} onClick={() => { const n = ask(`Why ${r.rollback_label?.toLowerCase() ?? "roll back"}?`); if (n) void run(r.id, () => rollbackRequest(r.id, n)); }}>
                    {r.rollback_label ?? "Roll back"}
                  </button>
                )}
                {["pending_approval", "approved"].includes(r.status) && canRun && (
                  <button className="button-secondary text-xs" disabled={busy} onClick={() => void run(r.id, () => cancelRequest(r.id))}>Cancel</button>
                )}
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              </div>
            </article>
          );
        })}
      </section>
    </div>
  );
}

export default function ResponsePage() {
  return (
    <Suspense fallback={<div className="page-state"><Loader2 className="h-5 w-5 animate-spin" /></div>}>
      <ResponseView />
    </Suspense>
  );
}
