import { apiFetch } from "./api";

export type ResponseStatus =
  | "pending_approval"
  | "approved"
  | "executing"
  | "succeeded"
  | "failed"
  | "rejected"
  | "cancelled"
  | "expired"
  | "rolled_back";

export const STATUS_LABELS: Record<ResponseStatus, string> = {
  pending_approval: "Awaiting approval",
  approved: "Approved",
  executing: "Executing",
  succeeded: "Done",
  failed: "Failed",
  rejected: "Rejected",
  cancelled: "Cancelled",
  expired: "Expired",
  rolled_back: "Rolled back",
};

export type ActionCapability = {
  label: string;
  target: "host" | "user" | "ip";
  rollback_label: string;
  rollback: boolean;
  dry_run: boolean;
  connector: string;
  configured: boolean;
};

export type Capabilities = {
  live_execution_enabled: boolean;
  approval_ttl_minutes: number;
  request_ttl_hours: number;
  max_live_per_hour: number;
  actions: Record<string, ActionCapability>;
};

export type Execution = {
  at: string;
  by: string;
  kind: "dry_run" | "execute" | "rollback";
  ok: boolean;
  summary: string;
  external_ref?: string | null;
  details?: Record<string, unknown>;
};

export type ResponseRequest = {
  id: string;
  action_type: string;
  action_label: string;
  rollback_label: string | null;
  target: string;
  reason: string;
  status: ResponseStatus;
  alert_id: string | null;
  incident_id: string | null;
  requested_by: { id: string; email: string };
  requested_at: string;
  preview: { status: "ok" | "error" | "not_configured"; summary: string; details?: Record<string, unknown> };
  approval?: { by: { email: string }; at: string; note: string | null; expires_at: string };
  rejection?: { by: { email: string }; at: string; note: string };
  executions: Execution[];
  can_rollback: boolean;
};

async function errorText(res: Response, fallback: string): Promise<string> {
  try {
    const data = await res.json();
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail) && data.detail[0]?.msg) return String(data.detail[0].msg);
  } catch {
    /* fall through */
  }
  return `${fallback} (${res.status})`;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await apiFetch(`/api/v1/response${path}`, {
    method: "POST",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await errorText(res, "Request failed"));
  return res.json();
}

export async function fetchCapabilities(): Promise<Capabilities> {
  const res = await apiFetch("/api/v1/response/capabilities");
  if (!res.ok) throw new Error("Unable to load response capabilities");
  return res.json();
}

export async function fetchResponseRequests(): Promise<ResponseRequest[]> {
  const res = await apiFetch("/api/v1/response");
  if (!res.ok) throw new Error("Unable to load response requests");
  return res.json();
}

export const createRequest = (input: { action_type: string; target: string; reason: string; incident_id?: string; alert_id?: string }) =>
  post<ResponseRequest>("", input);
export const approveRequest = (id: string, note?: string) => post<ResponseRequest>(`/${encodeURIComponent(id)}/approve`, { note });
export const rejectRequest = (id: string, note: string) => post<ResponseRequest>(`/${encodeURIComponent(id)}/reject`, { note });
export const cancelRequest = (id: string) => post<ResponseRequest>(`/${encodeURIComponent(id)}/cancel`);
export const dryRunRequest = (id: string) => post<ResponseRequest>(`/${encodeURIComponent(id)}/dry-run`);
export const executeRequest = (id: string) => post<ResponseRequest>(`/${encodeURIComponent(id)}/execute`);
export const rollbackRequest = (id: string, note: string) => post<ResponseRequest>(`/${encodeURIComponent(id)}/rollback`, { note });
