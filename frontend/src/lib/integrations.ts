import { apiFetch } from "./api";

export type Webhook = {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  consecutive_failures: number;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string | null;
  disabled_reason: string | null;
};

export type Delivery = {
  id: string;
  event_type: string;
  status: "pending" | "sending" | "delivered" | "dead";
  attempts: number;
  last_status_code: number | null;
  last_error: string | null;
  created_at: string;
  next_attempt_at: string | null;
  delivered_at: string | null;
};

export type ApiToken = {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  status: "active" | "expired" | "revoked";
  created_by: string | null;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
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

async function call<T>(path: string, method = "GET", body?: unknown, fallback = "Request failed"): Promise<T> {
  const res = await apiFetch(`/api/v1/integrations${path}`, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await errorText(res, fallback));
  return res.json();
}

export const fetchWebhooks = () => call<Webhook[]>("/webhooks");
export const fetchEventTypes = () => call<string[]>("/event-types");
export const createWebhook = (input: { name: string; url: string; events: string[] }) =>
  call<Webhook & { secret: string }>("/webhooks", "POST", input, "Unable to create webhook");
export const updateWebhook = (id: string, patch: Partial<Pick<Webhook, "name" | "url" | "events" | "enabled">>) =>
  call<Webhook>(`/webhooks/${encodeURIComponent(id)}`, "PATCH", patch, "Unable to update webhook");
export const deleteWebhook = (id: string) => call(`/webhooks/${encodeURIComponent(id)}`, "DELETE");
export const rotateWebhookSecret = (id: string) => call<{ secret: string }>(`/webhooks/${encodeURIComponent(id)}/rotate-secret`, "POST");
export const testWebhook = (id: string) => call<{ ok: boolean; status_code: number | null; error: string | null }>(`/webhooks/${encodeURIComponent(id)}/test`, "POST");
export const fetchDeliveries = (id: string) => call<Delivery[]>(`/webhooks/${encodeURIComponent(id)}/deliveries`);
export const redeliver = (webhookId: string, deliveryId: string) =>
  call(`/webhooks/${encodeURIComponent(webhookId)}/deliveries/${encodeURIComponent(deliveryId)}/redeliver`, "POST");

export const fetchScopes = () => call<Record<string, string>>("/scopes");
export const fetchTokens = () => call<ApiToken[]>("/tokens");
export const createToken = (input: { name: string; scopes: string[]; expires_in_days?: number }) =>
  call<ApiToken & { token: string }>("/tokens", "POST", input, "Unable to create token");
export const revokeToken = (id: string) => call(`/tokens/${encodeURIComponent(id)}`, "DELETE");
