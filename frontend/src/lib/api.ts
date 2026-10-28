import { API_BASE, getAccessToken, setAccessToken, clearTokens } from "./auth";

async function tryRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: "POST",
      credentials: "include", // Send HttpOnly cookie
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!res.ok) return false;
    const data = await res.json();
    setAccessToken(data.access_token);
    return true;
  } catch {
    return false;
  }
}

let refreshInFlight: Promise<boolean> | null = null;

export function refreshOnce(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = tryRefresh().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const access = getAccessToken();
  const headers = new Headers(options.headers);
  if (access) headers.set("Authorization", `Bearer ${access}`);

  let res = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers,
  });

  if (res.status === 401) {
    const refreshed = await refreshOnce();
    if (refreshed) {
      const retryHeaders = new Headers(options.headers);
      const newAccess = getAccessToken();
      if (newAccess) retryHeaders.set("Authorization", `Bearer ${newAccess}`);
      res = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: "include",
        headers: retryHeaders,
      });
    } else {
      clearTokens();
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.replace("/login");
      }
    }
  }

  return res;
}
