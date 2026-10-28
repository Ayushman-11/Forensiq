import { relativeTime, VERDICT_LABELS, type Verdict } from "@/lib/triage";
import type { AlertRecord } from "@/lib/types";

export const SEVERITY_COLOR: Record<string, string> = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#94A3B8",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLOR[severity?.toLowerCase()] ?? "#94A3B8";
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase border"
      style={{ color, borderColor: `${color}40`, backgroundColor: `${color}10` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {severity}
    </span>
  );
}

export function StatusBadge({ alert }: { alert: Pick<AlertRecord, "status" | "verdict"> }) {
  const verdict = alert.verdict as Verdict | undefined;
  return (
    <span
      className="font-mono text-[10px] uppercase font-semibold text-[var(--text-secondary)] px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-color)] whitespace-nowrap"
      title={verdict ? VERDICT_LABELS[verdict] : undefined}
    >
      {alert.status}
      {verdict ? ` · ${VERDICT_LABELS[verdict] ?? verdict}` : ""}
    </span>
  );
}

/** Remaining time to the next SLA deadline, red once breached. Hidden for resolved alerts. */
export function SlaBadge({ alert }: { alert: AlertRecord }) {
  const sla = alert.sla;
  if (!sla || alert.status === "Closed" || alert.status === "Suppressed") return null;
  const acked = !!alert.acknowledged_at;
  const breached = acked ? sla.resolve_breached : sla.ack_breached;
  const due = acked ? sla.resolve_due : sla.ack_due;
  const label = acked ? "Resolve" : "Ack";
  const color = breached ? "#EF4444" : "#94A3B8";
  return (
    <span
      className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border whitespace-nowrap"
      style={{ color, borderColor: `${color}50` }}
      title={`${label} due ${new Date(due).toLocaleString()}`}
    >
      {label} {breached ? `overdue ${relativeTime(due).replace(" ago", "")}` : relativeTime(due)}
    </span>
  );
}
