export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

const ACCESS_TOKEN_KEY = "forensiq_access_token";
const REFRESH_TOKEN_KEY = "forensiq_refresh_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(access: string, refresh: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(ACCESS_TOKEN_KEY, access);
  window.localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
}

export function clearTokens(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(ACCESS_TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export interface DecodedUser {
  email: string;
  role: string;
  sub: string;
}

export function decodeUser(accessToken: string): DecodedUser | null {
  try {
    const payloadSegment = accessToken.split(".")[1];
    if (!payloadSegment) return null;
    const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(base64));
    if (typeof json.email !== "string" || typeof json.role !== "string" || typeof json.sub !== "string") {
      return null;
    }
    return { email: json.email, role: json.role, sub: json.sub };
  } catch {
    return null;
  }
}
