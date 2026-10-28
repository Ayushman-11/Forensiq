import { apiFetch } from "./api";

export type Verdict = "true_positive" | "benign_true_positive" | "false_positive" | "duplicate";
export type DispositionAction = "close" | "escalate" | "suppress" | "reopen";
export type BulkAction = DispositionAction | "assign";

export type Sla = { ack_due: string; resolve_due: string; ack_breached: boolean; resolve_breached: boolean };
export type DirectoryUser = { id: string; email: string; role: string };
export type Note = { _id: string; content: string; author_email?: string; created_at: string };
export type AuditEntry = {
  _id: string;
  action: string;
  actor_email?: string;
  created_at: string;
  metadata?: { from?: string | null; to?: string | null; verdict?: string | null; note?: string; note_id?: string };
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  true_positive: "True positive",
  benign_true_positive: "Benign true positive",
  false_positive: "False positive",
  duplicate: "Duplicate",
};

export const VERDICT_HELP: Record<Verdict, string> = {
  true_positive: "Real malicious or unauthorised activity",
  benign_true_positive: "Rule fired correctly, activity was authorised (admin, pentest)",
  false_positive: "Rule fired on activity it should not match",
  duplicate: "Already tracked by another alert",
};

export const OPEN_STATUSES = ["New", "Investigating", "Investigated", "Investigation Failed", "Escalated"];
export const MANAGER_ROLES = ["soc_manager", "admin"];

/** Which actions the status machine allows from a status. Mirrors services/triage.py TRANSITIONS. */
export function allowedActions(status: string): DispositionAction[] {
  if (status === "Closed" || status === "Suppressed") return ["reopen"];
  if (status === "Escalated") return ["close", "suppress", "reopen"];
  return ["close", "escalate", "suppress"];
}

/** Why the current role may not do this, or null. The server enforces the same rule; this only explains it up front. */
export function roleBlock(role: string | undefined, severity: string, action: DispositionAction, verdict?: Verdict, status?: string): string | null {
  if (role && MANAGER_ROLES.includes(role)) return null;
  const high = ["critical", "high"].includes(severity.toLowerCase());
  if (action === "suppress" && high) return "Suppressing a high or critical alert needs a SOC manager";
  if (action === "close" && high && verdict && verdict !== "true_positive")
    return "Only a SOC manager can close a high or critical alert as anything but a true positive";
  if (action === "reopen" && status === "Suppressed") return "Reopening a suppressed alert needs a SOC manager";
  return null;
}

export const ACTION_LABELS: Record<BulkAction, string> = {
  close: "Close",
  escalate: "Escalate",
  suppress: "Suppress",
  reopen: "Reopen",
  assign: "Assign",
};

async function errorText(res: Response, fallback: string): Promise<string> {
  const body = await res.json().catch(() => ({}));
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}

export async function setDisposition(alertId: string, action: DispositionAction, note: string, verdict?: Verdict) {
  const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/disposition`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, note, verdict: verdict ?? null }),
  });
  if (!res.ok) throw new Error(await errorText(res, `Unable to ${action} alert`));
  return res.json();
}

export async function setAssignee(alertId: string, assigneeId: string | null) {
  const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/assignee`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ assignee_id: assigneeId }),
  });
  if (!res.ok) throw new Error(await errorText(res, "Unable to change assignee"));
  return res.json();
}

export type BulkResult = { succeeded: number; failed: number; results: { alert_id: string; ok: boolean; error?: string }[] };

export async function bulkAction(
  alertIds: string[],
  action: BulkAction,
  opts: { note?: string; verdict?: Verdict; assigneeId?: string | null } = {},
): Promise<BulkResult> {
  const res = await apiFetch("/api/v1/alerts/bulk", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      alert_ids: alertIds,
      action,
      note: opts.note ?? null,
      verdict: opts.verdict ?? null,
      assignee_id: opts.assigneeId ?? null,
    }),
  });
  if (!res.ok) throw new Error(await errorText(res, "Bulk action failed"));
  return res.json();
}

export async function fetchUsers(): Promise<DirectoryUser[]> {
  const res = await apiFetch("/api/v1/users");
  if (!res.ok) throw new Error("Unable to load users");
  return res.json();
}

export async function fetchNotes(alertId: string): Promise<Note[]> {
  const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/notes`);
  if (!res.ok) throw new Error("Unable to load notes");
  return res.json();
}

export async function addNote(alertId: string, content: string): Promise<Note> {
  const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  if (!res.ok) throw new Error(await errorText(res, "Unable to add note"));
  return res.json();
}

export async function fetchAudit(alertId: string): Promise<AuditEntry[]> {
  const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/audit`);
  if (!res.ok) throw new Error("Unable to load activity");
  return res.json();
}

export function relativeTime(value?: string | null): string {
  if (!value) return "—";
  const diffMs = Date.now() - new Date(value).getTime();
  const future = diffMs < 0;
  const m = Math.round(Math.abs(diffMs) / 60000);
  const text = m < 1 ? "now" : m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`;
  if (text === "now") return "just now";
  return future ? `in ${text}` : `${text} ago`;
}
