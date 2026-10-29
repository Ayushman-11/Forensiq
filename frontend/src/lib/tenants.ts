import { apiFetch } from "./api";

export type TenantSettings = {
  id: string;
  name: string;
  status: "active" | "suspended";
  registered: boolean;
  is_platform: boolean;
  siem: {
    enabled: boolean;
    configured: boolean;
    type: "splunk" | "elastic";
    api_key_set: boolean;
    source: "tenant" | "platform" | "none";
    url: string;
    username: string;
    password_set: boolean;
    verify_ssl: boolean;
    detection_index: string;
    allowed_indexes: string[];
    poll_interval_seconds: number;
  };
  threat_intel: {
    virustotal: { configured: boolean; source: "tenant" | "platform" | "none" };
    abuseipdb: { configured: boolean; source: "tenant" | "platform" | "none" };
    otx: { configured: boolean; source: "tenant" | "platform" | "none" };
    greynoise: { configured: boolean; source: "tenant" | "platform" | "none" };
    misp: { configured: boolean; source: "tenant" | "platform" | "none"; url: string };
  };
  noise: { source: "tenant" | "platform"; benign_domains?: string[]; shared_hosting_domains?: string[]; suppress?: unknown[] };
};

export type TenantRow = {
  id: string;
  name: string;
  status: "active" | "suspended";
  registered: boolean;
  is_platform: boolean;
  users: number;
  siem_configured: boolean;
  last_poll_at: string | null;
  last_error: string | null;
};

/** Fields a secret may take: undefined = keep what is stored, "" = clear it, anything else = replace it. */
export type SettingsUpdate = {
  reason: string;
  siem?: {
    type?: "splunk" | "elastic";
    api_key?: string;
    enabled?: boolean;
    url?: string;
    username?: string;
    password?: string;
    verify_ssl?: boolean;
    detection_index?: string;
    allowed_indexes?: string[];
    poll_interval_seconds?: number;
  };
  threat_intel?: {
    vt_api_key?: string;
    abuseipdb_api_key?: string;
    otx_api_key?: string;
    greynoise_api_key?: string;
    misp_url?: string;
    misp_api_key?: string;
  };
  noise?: { benign_domains: string[]; shared_hosting_domains: string[]; suppress: unknown[] };
  reset_noise?: boolean;
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

async function json<T>(path: string, method: string, body?: unknown, fallback = "Request failed"): Promise<T> {
  const res = await apiFetch(`/api/v1/tenants${path}`, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await errorText(res, fallback));
  return res.json();
}

const base = (orgId?: string) => (orgId ? `/${encodeURIComponent(orgId)}/settings` : "/current/settings");

export const fetchSettings = (orgId?: string) => json<TenantSettings>(base(orgId), "GET", undefined, "Unable to load settings");
export const saveSettings = (update: SettingsUpdate, orgId?: string) =>
  json<{ changed: string[]; settings: TenantSettings }>(base(orgId), "PUT", update, "Unable to save settings");
export const testSiem = (orgId?: string) => json<{ ok: boolean; detail: string }>(`${base(orgId)}/siem/test`, "POST", undefined, "Test failed");

/** Platform administrators only: a 403 here simply means "not a platform admin". */
export async function fetchTenants(): Promise<TenantRow[] | null> {
  const res = await apiFetch("/api/v1/tenants");
  if (res.status === 403) return null;
  if (!res.ok) throw new Error("Unable to load tenants");
  return res.json();
}
export const createTenant = (input: { id: string; name: string; admin_email: string; admin_password: string }) =>
  json<{ id: string }>("", "POST", input, "Unable to create tenant");
export const setTenantStatus = (orgId: string, status: "active" | "suspended") =>
  json<{ id: string }>(`/${encodeURIComponent(orgId)}`, "PATCH", { status }, "Unable to change status");
