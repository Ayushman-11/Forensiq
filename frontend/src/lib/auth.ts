export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

// In-memory token storage to defend against XSS account takeover
let _inMemoryAccessToken: string | null = null;

export function getAccessToken(): string | null {
  return _inMemoryAccessToken;
}

export function setAccessToken(token: string | null): void {
  _inMemoryAccessToken = token;
}

export function clearTokens(): void {
  _inMemoryAccessToken = null;
  if (typeof window !== "undefined") {
    // Clean up any legacy localStorage tokens from older sessions
    window.localStorage.removeItem("forensiq_access_token");
    window.localStorage.removeItem("forensiq_refresh_token");
  }
}

export interface DecodedUser {
  email: string;
  role: string;
  sub: string;
  org_id?: string;
}

export function decodeUser(accessToken: string): DecodedUser | null {
  try {
    const payloadSegment = accessToken.split(".")[1];
    if (!payloadSegment) return null;
    const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const json = JSON.parse(atob(padded));
    if (typeof json.email !== "string" || typeof json.role !== "string" || typeof json.sub !== "string") {
      return null;
    }
    return { email: json.email, role: json.role, sub: json.sub, org_id: json.org_id };
  } catch {
    return null;
  }
}

/**
 * Fetches a single-use ticket for connecting WebSocket streams securely without
 * leaking access tokens into query strings.
 */
export async function getWsTicket(): Promise<string | null> {
  const token = getAccessToken();
  if (!token) return null;
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/ws-ticket`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.ticket || null;
  } catch {
    return null;
  }
}
