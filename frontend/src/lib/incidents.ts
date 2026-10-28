import { apiFetch } from "./api";
import type { Sla } from "./triage";

export type CaseStatus = "open" | "in_progress" | "resolved" | "closed";
export const CASE_STATUSES: CaseStatus[] = ["open", "in_progress", "resolved", "closed"];
export const CASE_STATUS_LABELS: Record<CaseStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  closed: "Closed",
};

export type TicketSystem = "jira" | "servicenow";

export type IncidentTicket = {
  id: string;
  system: TicketSystem;
  key: string;
  url: string;
  external_status: string;
  mapped_status: CaseStatus | null;
  sync_state: "ok" | "error" | "not_configured";
  sync_error: string | null;
  last_synced_at: string | null;
  linked_by: string;
};

export type IncidentNote = { _id: string; content: string; author_email: string; created_at: string };
export type TimelineEntry = { type: string; at: string; actor: string | null; data: Record<string, unknown> };

export type IncidentSummary = {
  id: string;
  title: string;
  severity: string;
  state: "open" | "resolved";
  /** The case's own status, set by analysts (distinct from the derived `state`). */
  status: CaseStatus;
  case_owner: string | null;
  case_owner_id: string | null;
  manual: boolean;
  tickets: IncidentTicket[];
  alert_count: number;
  open_count: number;
  unassigned_open: number;
  owner: string | null;
  mixed_owners: boolean;
  status_counts: Record<string, number>;
  hosts: string[];
  users: string[];
  rules: string[];
  first_seen: string | null;
  last_seen: string | null;
};

export type IncidentMember = {
  _id: string;
  title: string;
  severity: string;
  status: string;
  host?: string;
  user?: string;
  rule_name?: string;
  assignee_id?: string;
  assignee_email?: string;
  verdict?: string;
  risk_score?: number;
  dns_query?: string;
  command_line?: string;
  first_seen?: string;
  detected_at?: string;
  acknowledged_at?: string;
  sla?: Sla | null;
};

export type IncidentDetail = IncidentSummary & {
  link_keys: string[];
  alerts: IncidentMember[];
  resolution_note: string | null;
  merged_from: string[];
  split_from: string | null;
  pinned_alert_ids: string[];
};

export async function fetchIncidents(state: "open" | "resolved" | "all"): Promise<IncidentSummary[]> {
  const res = await apiFetch(`/api/v1/incidents?state=${state}`);
  if (!res.ok) throw new Error("Unable to load incidents");
  return res.json();
}

export async function fetchIncident(id: string): Promise<IncidentDetail | null> {
  const res = await apiFetch(`/api/v1/incidents/${encodeURIComponent(id)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Unable to load incident");
  return res.json();
}

export async function rebuildIncidents(): Promise<{ alerts: number; linked: number; incidents: number }> {
  const res = await apiFetch("/api/v1/incidents/rebuild", { method: "POST" });
  if (!res.ok) throw new Error("Only a SOC manager or admin can regroup incidents");
  return res.json();
}

/** Why a link key grouped alerts, in analyst words. */
export function describeKey(key: string): string {
  const [kind, ...rest] = key.split(":");
  const value = rest.join(":");
  switch (kind) {
    case "host": return `Same host: ${value}`;
    case "user": return `Same account: ${value}`;
    case "hash": return `Same file hash: ${value.slice(0, 16)}…`;
    case "domain": return `Same domain: ${value}`;
    default: return key;
  }
}

/** POST/DELETE a case action; surfaces the server's reason (validation, role, conflict) to the analyst. */
async function caseAction<T>(id: string, path: string, method: "POST" | "DELETE", body?: unknown): Promise<T> {
  const res = await apiFetch(`/api/v1/incidents/${encodeURIComponent(id)}${path}`, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") detail = data.detail;
    } catch {
      /* keep the generic message */
    }
    throw new Error(detail);
  }
  return res.json();
}

export const setCaseStatus = (id: string, status: CaseStatus, note?: string, force = false) =>
  caseAction<{ status: CaseStatus }>(id, "/status", "POST", { status, note, force });
export const setCaseOwner = (id: string, ownerId: string | null) => caseAction(id, "/owner", "POST", { owner_id: ownerId });
export const addIncidentNote = (id: string, content: string) => caseAction<IncidentNote>(id, "/notes", "POST", { content });
export const mergeIncidents = (id: string, sourceIds: string[], note: string) =>
  caseAction(id, "/merge", "POST", { source_ids: sourceIds, note });
export const splitIncident = (id: string, alertIds: string[], note: string, title?: string) =>
  caseAction<{ new_incident_id: string }>(id, "/split", "POST", { alert_ids: alertIds, note, title: title || undefined });
export const pinAlert = (id: string, alertId: string) => caseAction(id, "/pin", "POST", { alert_id: alertId });
export const unpinAlert = (id: string, alertId: string) => caseAction(id, `/pin/${encodeURIComponent(alertId)}`, "DELETE");
export const linkTicket = (id: string, system: TicketSystem, key?: string, create = false) =>
  caseAction<IncidentTicket>(id, "/tickets", "POST", { system, key: key || undefined, create });
export const syncTicket = (id: string, ticketId: string) =>
  caseAction<{ applied_status: CaseStatus | null }>(id, `/tickets/${encodeURIComponent(ticketId)}/sync`, "POST");
export const unlinkTicket = (id: string, ticketId: string) => caseAction(id, `/tickets/${encodeURIComponent(ticketId)}`, "DELETE");

export async function fetchIncidentNotes(id: string): Promise<IncidentNote[]> {
  const res = await apiFetch(`/api/v1/incidents/${encodeURIComponent(id)}/notes`);
  if (!res.ok) throw new Error("Unable to load notes");
  return res.json();
}

export async function fetchIncidentTimeline(id: string): Promise<TimelineEntry[]> {
  const res = await apiFetch(`/api/v1/incidents/${encodeURIComponent(id)}/timeline`);
  if (!res.ok) throw new Error("Unable to load timeline");
  return res.json();
}

/** One line per timeline entry, in analyst words. */
export function describeTimelineEntry(e: TimelineEntry): string {
  const d = e.data as Record<string, string | string[] | null | undefined>;
  switch (e.type) {
    case "alert_detected": return `Detected: ${d.title ?? d.alert_id}`;
    case "alert_resolved": return `Alert closed${d.verdict ? ` (${d.verdict})` : ""}: ${d.title ?? d.alert_id}`;
    case "note_added": return `Note: ${d.preview ?? ""}`;
    case "status_changed": return `Status ${d.from} -> ${d.to}${d.note ? `: ${d.note}` : ""}${d.source ? ` (via ${d.source})` : ""}`;
    case "owner_changed": return `Owner ${d.from ?? "nobody"} -> ${d.to ?? "nobody"}`;
    case "merged": return `Merged ${(d.sources as string[] | undefined)?.length ?? 0} incident(s) in: ${d.note ?? ""}`;
    case "split": return `Split ${(d.alert_ids as string[] | undefined)?.length ?? 0} alert(s) into a new incident: ${d.note ?? ""}`;
    case "created_by_split": return `Created by splitting another incident: ${d.note ?? ""}`;
    case "alert_pinned": return `Pinned alert: ${d.title ?? d.alert_id}`;
    case "alert_unpinned": return `Unpinned alert ${d.alert_id}`;
    case "alert_moved_out": return `Alert ${d.alert_id} moved to another incident`;
    case "ticket_linked": return `Linked ${d.system} ticket ${d.key}`;
    case "ticket_created": return `Created ${d.system} ticket ${d.key}`;
    case "ticket_unlinked": return `Unlinked ${d.system} ticket ${d.key}`;
    case "ticket_synced": return `Ticket ${d.key}: ${d.from} -> ${d.to}`;
    default: return e.type.replace(/_/g, " ");
  }
}
