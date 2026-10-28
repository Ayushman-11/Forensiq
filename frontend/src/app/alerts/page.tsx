"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { CircleAlert, Keyboard, Loader2, RefreshCw, Search, X } from "lucide-react";
import DispositionDialog from "@/components/triage/DispositionDialog";
import { SeverityBadge, SlaBadge, StatusBadge } from "@/components/triage/Badges";
import { useAuth } from "@/context/AuthContext";
import { apiFetch } from "@/lib/api";
import {
  MANAGER_ROLES,
  bulkAction,
  fetchUsers,
  relativeTime,
  type BulkResult,
  type DirectoryUser,
  type DispositionAction,
} from "@/lib/triage";
import type { AlertRecord } from "@/lib/types";

type View = { key: string; label: string; status: string; assignee?: string };

const VIEWS: View[] = [
  { key: "mine", label: "My open", status: "open", assignee: "me" },
  { key: "unassigned", label: "Unassigned", status: "open", assignee: "unassigned" },
  { key: "open", label: "All open", status: "open" },
  { key: "escalated", label: "Escalated", status: "Escalated" },
  { key: "closed", label: "Closed", status: "Closed" },
  { key: "suppressed", label: "Suppressed", status: "Suppressed" },
  { key: "all", label: "Everything", status: "All" },
];

const SORTS = [
  { key: "severity", label: "Severity" },
  { key: "newest", label: "Newest" },
  { key: "oldest", label: "Oldest" },
  { key: "risk", label: "Risk score" },
];

function cleanTitle(title: string) {
  return title.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i, "").trim();
}

/** The field that tells otherwise identical alerts apart. */
function distinguishing(a: AlertRecord): string | undefined {
  return a.dns_query || a.command_line || (a.dest_ip ? `${a.dest_ip}${a.dest_port ? `:${a.dest_port}` : ""}` : undefined) || a.registry_key || undefined;
}

export default function AlertsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user } = useAuth();
  const isManager = !!user && MANAGER_ROLES.includes(user.role);

  const [viewKey, setViewKey] = useState(searchParams.get("view") ?? "open");
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const [severity, setSeverity] = useState("All");
  const [sort, setSort] = useState(searchParams.get("sort") ?? "severity");
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [cursor, setCursor] = useState(0);
  const [dialog, setDialog] = useState<DispositionAction | null>(null);
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showKeys, setShowKeys] = useState(false);
  const searchRef = useRef<HTMLInputElement | null>(null);

  const view = VIEWS.find((v) => v.key === viewKey) ?? VIEWS[2];

  // Old deep links (/alerts?alert=<id>) go to the detail page.
  useEffect(() => {
    const legacy = searchParams.get("alert");
    if (legacy) router.replace(`/alerts/${encodeURIComponent(legacy)}`);
  }, [router, searchParams]);

  const load = useCallback(async () => {
    try {
      setError(null);
      const p = new URLSearchParams({ limit: "200", sort, status: view.status });
      if (view.assignee) p.set("assignee", view.assignee);
      if (search.trim()) p.set("search", search.trim());
      if (severity !== "All") p.set("severity", severity);
      const r = await apiFetch(`/api/v1/alerts?${p}`);
      if (!r.ok) throw new Error("Unable to load alert queue");
      const next = (await r.json()) as AlertRecord[];
      setAlerts(next);
      setSelected((prev) => new Set([...prev].filter((id) => next.some((a) => a._id === id))));
      setCursor((c) => Math.min(c, Math.max(0, next.length - 1)));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load alert queue");
    } finally {
      setLoading(false);
    }
  }, [search, severity, sort, view.assignee, view.status]);

  useEffect(() => {
    const t = setTimeout(() => void load(), search ? 250 : 0);
    return () => clearTimeout(t);
  }, [load, search]);

  useEffect(() => {
    fetchUsers().then(setUsers).catch(() => setUsers([]));
  }, []);

  // Keep the view, sort and search in the URL so a queue can be bookmarked or shared.
  useEffect(() => {
    const p = new URLSearchParams();
    if (viewKey !== "open") p.set("view", viewKey);
    if (sort !== "severity") p.set("sort", sort);
    if (search.trim()) p.set("search", search.trim());
    const qs = p.toString();
    window.history.replaceState(null, "", qs ? `/alerts?${qs}` : "/alerts");
  }, [viewKey, sort, search]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, breached: 0 };
    for (const a of alerts) {
      if (a.severity === "critical") c.critical++;
      if (a.severity === "high") c.high++;
      if (a.sla && (a.acknowledged_at ? a.sla.resolve_breached : a.sla.ack_breached) && !["Closed", "Suppressed"].includes(a.status)) c.breached++;
    }
    return c;
  }, [alerts]);

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const allSelected = alerts.length > 0 && selected.size === alerts.length;

  const runBulk = async (fn: () => Promise<BulkResult>) => {
    setBusy(true);
    setBulkMsg(null);
    try {
      const res = await fn();
      const failures = res.results.filter((r) => !r.ok);
      const reasons = [...new Set(failures.map((f) => f.error))].join("; ");
      setBulkMsg(`${res.succeeded} updated${res.failed ? `, ${res.failed} not changed: ${reasons}` : ""}`);
      setSelected(new Set(failures.map((f) => f.alert_id)));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Bulk action failed");
    } finally {
      setBusy(false);
    }
  };

  // Queue keyboard: j/k move, x select, Enter or o open, a assign to me, / search, ? help.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (dialog || e.ctrlKey || e.metaKey || e.altKey) return;
      if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) {
        if (e.key === "Escape") target.blur();
        return;
      }
      const current = alerts[cursor];
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => Math.min(c + 1, alerts.length - 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      } else if (e.key === "x" && current) {
        e.preventDefault();
        toggle(current._id);
      } else if ((e.key === "Enter" || e.key === "o") && current) {
        e.preventDefault();
        router.push(`/alerts/${encodeURIComponent(current._id)}`);
      } else if (e.key === "a" && current && user) {
        e.preventDefault();
        void runBulk(() => bulkAction([current._id], "assign", { assigneeId: user.sub }));
      } else if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "?") {
        setShowKeys((s) => !s);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  useEffect(() => {
    document.getElementById(`alert-row-${cursor}`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const selectedAlerts = alerts.filter((a) => selected.has(a._id));

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-4 pb-12">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">Alerts</h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">Triage queue · assign, investigate and resolve.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowKeys((s) => !s)} className="button-secondary text-xs" aria-label="Keyboard shortcuts">
            <Keyboard className="h-3.5 w-3.5" />
          </button>
          <button onClick={() => void load()} className="button-secondary text-xs">
            <RefreshCw className="h-3.5 w-3.5" /> <span>Refresh</span>
          </button>
        </div>
      </header>

      {showKeys && (
        <div className="card p-3 text-xs text-[var(--text-secondary)] flex flex-wrap gap-x-5 gap-y-1">
          <span><kbd>j</kbd>/<kbd>k</kbd> move</span>
          <span><kbd>x</kbd> select</span>
          <span><kbd>Enter</kbd> open</span>
          <span><kbd>a</kbd> assign to me</span>
          <span><kbd>/</kbd> search</span>
          <span>On an alert: <kbd>c</kbd> close, <kbd>e</kbd> escalate, <kbd>s</kbd> suppress, <kbd>n</kbd> note</span>
        </div>
      )}

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Views */}
      <nav className="flex flex-wrap gap-1" aria-label="Queue views">
        {VIEWS.map((v) => (
          <button
            key={v.key}
            onClick={() => {
              setViewKey(v.key);
              setSelected(new Set());
              setCursor(0);
            }}
            aria-current={v.key === viewKey ? "page" : undefined}
            className={`px-3 py-1.5 rounded text-xs font-medium border ${
              v.key === viewKey
                ? "bg-[var(--surface-primary)] border-[var(--text-primary)] text-[var(--text-primary)]"
                : "border-[var(--border-color)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            {v.label}
          </button>
        ))}
      </nav>

      {/* Filters */}
      <section className="card flex flex-wrap items-center gap-3 p-3">
        <div className="relative min-w-[240px] flex-1">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            ref={searchRef}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, host, user, rule, DNS query, technique…  ( / )"
            aria-label="Search alerts"
            className="field w-full pl-9 h-8 text-xs"
          />
        </div>
        <div className="flex items-center gap-1 bg-[var(--surface-secondary)] p-0.5 rounded border border-[var(--border-color)]">
          {["All", "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverity(sev)}
              aria-pressed={severity === sev}
              className={`px-2.5 py-1 rounded text-xs font-medium capitalize ${
                severity === sev ? "bg-[var(--surface-primary)] text-[var(--text-primary)] font-semibold" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
          Sort
          <select value={sort} onChange={(e) => setSort(e.target.value)} className="field h-8 text-xs cursor-pointer">
            {SORTS.map((s) => (
              <option key={s.key} value={s.key}>{s.label}</option>
            ))}
          </select>
        </label>
        <div className="flex items-center gap-3 text-xs font-mono border-l border-[var(--border-color)] pl-3">
          <span className="text-[var(--text-muted)]">{alerts.length} shown</span>
          <span className="text-[#EF4444] font-semibold">{counts.critical} critical</span>
          <span className="text-[#F59E0B] font-semibold">{counts.high} high</span>
          {counts.breached > 0 && <span className="text-[#EF4444]">{counts.breached} SLA overdue</span>}
        </div>
      </section>

      {/* Bulk bar */}
      {selected.size > 0 && (
        <section className="card p-2.5 flex flex-wrap items-center gap-2 text-xs sticky top-2 z-20" aria-label="Bulk actions">
          <span className="font-semibold text-[var(--text-primary)] mr-1">{selected.size} selected</span>
          {user && (
            <button disabled={busy} onClick={() => void runBulk(() => bulkAction([...selected], "assign", { assigneeId: user.sub }))} className="button-secondary text-xs">
              Assign to me
            </button>
          )}
          {isManager && (
            <select
              disabled={busy}
              value=""
              onChange={(e) => {
                const id = e.target.value;
                if (id) void runBulk(() => bulkAction([...selected], "assign", { assigneeId: id === "__none" ? null : id }));
              }}
              className="field h-8 text-xs cursor-pointer"
              aria-label="Assign selected to"
            >
              <option value="">Assign to…</option>
              <option value="__none">Unassign</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.email}</option>
              ))}
            </select>
          )}
          <button disabled={busy} onClick={() => setDialog("close")} className="button-primary text-xs">Close…</button>
          <button disabled={busy} onClick={() => setDialog("escalate")} className="button-secondary text-xs">Escalate…</button>
          <button disabled={busy} onClick={() => setDialog("suppress")} className="button-secondary text-xs">Suppress…</button>
          <button onClick={() => setSelected(new Set())} className="ml-auto p-1 rounded hover:bg-[var(--surface-hover)]" aria-label="Clear selection">
            <X className="w-4 h-4" />
          </button>
          {busy && <Loader2 className="w-4 h-4 animate-spin" />}
        </section>
      )}
      {bulkMsg && <p className="text-xs text-[var(--text-secondary)]">{bulkMsg}</p>}

      {/* Table */}
      <section className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[900px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--surface-secondary)] text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                <th className="py-2.5 pl-4 w-8">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={() => setSelected(allSelected ? new Set() : new Set(alerts.map((a) => a._id)))}
                    aria-label="Select all shown alerts"
                  />
                </th>
                <th className="py-2.5 px-3 w-24">Severity</th>
                <th className="py-2.5 px-3">Alert</th>
                <th className="py-2.5 px-3 w-36">Host</th>
                <th className="py-2.5 px-3 w-40">Assignee</th>
                <th className="py-2.5 px-3 w-32">SLA</th>
                <th className="py-2.5 px-3 w-40">Status</th>
                <th className="py-2.5 px-3 w-24">Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-color)] text-xs">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)]">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" /> Loading alert queue…
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)]">
                    {view.key === "mine" ? "Nothing assigned to you. Pick from Unassigned." : "No alerts match this view."}
                  </td>
                </tr>
              ) : (
                alerts.map((a, i) => {
                  const detail = distinguishing(a);
                  const href = `/alerts/${encodeURIComponent(a._id)}`;
                  return (
                    <tr
                      key={a._id}
                      id={`alert-row-${i}`}
                      onClick={() => {
                        setCursor(i);
                        router.push(href);
                      }}
                      className={`cursor-pointer ${i === cursor ? "outline outline-1 -outline-offset-1 outline-[var(--text-muted)]" : ""} ${
                        selected.has(a._id) ? "bg-[var(--sidebar-active-bg)]" : "hover:bg-[var(--surface-hover)]"
                      }`}
                    >
                      <td className="py-3 pl-4" onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={selected.has(a._id)} onChange={() => toggle(a._id)} aria-label={`Select ${cleanTitle(a.title)}`} />
                      </td>
                      <td className="py-3 px-3"><SeverityBadge severity={a.severity} /></td>
                      <td className="py-3 px-3 max-w-0">
                        <Link href={href} onClick={(e) => e.stopPropagation()} className="font-semibold text-[var(--text-primary)] block truncate hover:underline">
                          {cleanTitle(a.title)}
                        </Link>
                        <span className="block truncate font-mono text-[10px] text-[var(--text-muted)]" title={detail}>
                          {a.rule_name}{detail ? ` · ${detail}` : ""}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-[var(--text-secondary)] truncate">{a.host || "—"}</td>
                      <td className="py-3 px-3 truncate text-[var(--text-secondary)]">
                        {a.assignee_email ? (a.assignee_id === user?.sub ? "You" : a.assignee_email) : <span className="text-[var(--text-muted)]">Unassigned</span>}
                      </td>
                      <td className="py-3 px-3"><SlaBadge alert={a} /></td>
                      <td className="py-3 px-3"><StatusBadge alert={a} /></td>
                      <td className="py-3 px-3 font-mono text-[var(--text-muted)] whitespace-nowrap" title={a.detected_at ? new Date(a.detected_at).toLocaleString() : undefined}>
                        {relativeTime(a.detected_at ?? a.created_at)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {dialog && (
        <DispositionDialog
          action={dialog}
          count={selected.size}
          // Role limits are shown per alert in the result; pass severity only when every selected alert shares it.
          severity={new Set(selectedAlerts.map((a) => a.severity)).size === 1 ? selectedAlerts[0]?.severity : undefined}
          role={user?.role}
          onCancel={() => setDialog(null)}
          onConfirm={async ({ note, verdict }) => {
            const action = dialog;
            setDialog(null);
            await runBulk(() => bulkAction([...selected], action, { note, verdict }));
          }}
        />
      )}
    </div>
  );
}
