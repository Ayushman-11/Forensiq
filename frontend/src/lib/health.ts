"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "./api";

export type ComponentState = "ok" | "degraded" | "stale" | "error" | "down" | "never" | "not_configured";

export type FeedHealth = { feed: string; state: ComponentState; recent_errors?: number };

export type SystemHealth = {
  siem: { state: ComponentState; detail: string };
  ingestion: { state: ComponentState; detail: string; last_run_at: string | null; lag_seconds?: number | null };
  threat_intel: { state: ComponentState; feeds: FeedHealth[] };
  ai: { state: ComponentState; mode: "llm" | "rules"; detail: string };
  checked_at: string;
};

export const STATE_COLOR: Record<ComponentState, string> = {
  ok: "#22C55E",
  degraded: "#F59E0B",
  stale: "#F59E0B",
  not_configured: "#F59E0B",
  never: "#94A3B8",
  error: "#EF4444",
  down: "#EF4444",
};

export const STATE_LABEL: Record<ComponentState, string> = {
  ok: "OK",
  degraded: "Degraded",
  stale: "Stale",
  not_configured: "Not configured",
  never: "Never run",
  error: "Error",
  down: "Down",
};

const POLL_MS = 60_000;

/** Live dependency status from the backend. `null` health means unknown, never assume healthy. */
export function useSystemHealth() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [unreachable, setUnreachable] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const res = await apiFetch("/api/v1/dashboard/system-health");
      if (!res.ok) throw new Error(String(res.status));
      setHealth((await res.json()) as SystemHealth);
      setUnreachable(false);
    } catch {
      setHealth(null);
      setUnreachable(true);
    }
  }, []);

  useEffect(() => {
    const first = setTimeout(() => void refresh(), 0);
    const timer = setInterval(() => void refresh(), POLL_MS);
    return () => {
      clearTimeout(first);
      clearInterval(timer);
    };
  }, [refresh]);

  return { health, unreachable, refresh };
}
