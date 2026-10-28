import { apiFetch } from "./api";
import type { Sla } from "./triage";

export type IncidentSummary = {
  id: string;
  title: string;
  severity: string;
  state: "open" | "resolved";
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

export type IncidentDetail = IncidentSummary & { link_keys: string[]; alerts: IncidentMember[] };

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
