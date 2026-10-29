"use client";

import { useCallback, useEffect, useState } from "react";
import { CircleAlert, Copy, Loader2 } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { relativeTime } from "@/lib/triage";
import {
  createToken,
  createWebhook,
  deleteWebhook,
  fetchDeliveries,
  fetchEventTypes,
  fetchScopes,
  fetchTokens,
  fetchWebhooks,
  redeliver,
  revokeToken,
  rotateWebhookSecret,
  testWebhook,
  updateWebhook,
  type ApiToken,
  type Delivery,
  type Webhook,
} from "@/lib/integrations";

type Reveal = { title: string; value: string } | null;

export default function IntegrationsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [hooks, setHooks] = useState<Webhook[] | null>(null);
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [scopes, setScopes] = useState<Record<string, string>>({});
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [reveal, setReveal] = useState<Reveal>(null);
  const [busy, setBusy] = useState(false);
  const [hook, setHook] = useState({ name: "", url: "", events: ["*"] as string[] });
  const [tok, setTok] = useState({ name: "", scopes: [] as string[], days: "90" });
  const [open, setOpen] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);

  const load = useCallback(async () => {
    try {
      const [h, t, s, e] = await Promise.all([fetchWebhooks(), fetchTokens(), fetchScopes(), fetchEventTypes()]);
      setHooks(h);
      setTokens(t);
      setScopes(s);
      setEventTypes(e);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load integrations");
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    const t = setTimeout(() => void load(), 0);
    return () => clearTimeout(t);
  }, [isAdmin, load]);

  const act = async (fn: () => Promise<unknown>, success?: string) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await fn();
      if (success) setInfo(success);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const showDeliveries = async (id: string) => {
    if (open === id) return setOpen(null);
    try {
      setDeliveries(await fetchDeliveries(id));
      setOpen(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load deliveries");
    }
  };

  const toggle = (list: string[], value: string) => (list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);

  if (!isAdmin) return <div className="page-state">Integrations are for administrators.</div>;
  const field = "field h-8 text-xs";

  return (
    <div className="mx-auto flex max-w-[1200px] flex-col gap-4 pb-12">
      <header className="border-b border-[var(--border-color)] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">Integrations</h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Send events to your SOAR or ticketing system with signed webhooks, or let a service account call the API with a scoped token.
        </p>
      </header>

      {error && <div className="feedback-error" role="alert"><CircleAlert className="h-4 w-4 shrink-0" /><span>{error}</span></div>}
      {info && <p role="status" className="text-xs text-[var(--text-secondary)]">{info}</p>}
      {reveal && (
        <div className="card p-4 space-y-2 border border-[var(--border-color)]" role="alert">
          <p className="text-xs font-semibold text-[var(--text-primary)]">{reveal.title}</p>
          <div className="flex items-center gap-2">
            <code className="font-mono text-xs break-all flex-1">{reveal.value}</code>
            <button className="button-secondary text-xs" aria-label="Copy" onClick={() => void navigator.clipboard?.writeText(reveal.value)}><Copy className="h-3.5 w-3.5" /></button>
          </div>
          <p className="text-[11px] text-[var(--text-muted)]">Store it now. It is not shown again.</p>
          <button className="button-secondary text-xs" onClick={() => setReveal(null)}>I have saved it</button>
        </div>
      )}

      <section className="card p-4 space-y-3" aria-label="Webhooks">
        <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">Webhooks</h2>
        {hooks === null && <Loader2 className="h-4 w-4 animate-spin" />}
        {hooks?.length === 0 && <p className="text-xs text-[var(--text-muted)]">No webhooks yet.</p>}
        {hooks?.map((h) => (
          <div key={h.id} className="border border-[var(--border-color)] rounded p-3 space-y-2 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold text-sm">{h.name}</span>
              <span className="font-mono text-[var(--text-muted)] break-all">{h.url}</span>
              <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded border border-[var(--border-color)]">{h.enabled ? "enabled" : "disabled"}</span>
            </div>
            <p className="text-[var(--text-muted)]">Events: {h.events.join(", ")}{h.last_success_at ? ` · last success ${relativeTime(h.last_success_at)}` : ""}{h.consecutive_failures ? ` · ${h.consecutive_failures} failures in a row` : ""}{h.last_error ? ` (${h.last_error})` : ""}</p>
            {h.disabled_reason && <p className="text-[#EF4444]">{h.disabled_reason}</p>}
            <div className="flex flex-wrap gap-1.5">
              <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(async () => { const r = await testWebhook(h.id); setInfo(r.ok ? "Test delivered (HTTP " + r.status_code + ")" : "Test failed: " + (r.error ?? "no response")); })}>Send test</button>
              <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(() => updateWebhook(h.id, { enabled: !h.enabled }))}>{h.enabled ? "Disable" : "Enable"}</button>
              <button className="button-secondary text-xs" disabled={busy} onClick={() => void showDeliveries(h.id)}>{open === h.id ? "Hide deliveries" : "Deliveries"}</button>
              <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(async () => { const r = await rotateWebhookSecret(h.id); setReveal({ title: `New signing secret for ${h.name}`, value: r.secret }); })}>Rotate secret</button>
              <button className="button-secondary text-xs" disabled={busy} onClick={() => { if (window.confirm(`Delete ${h.name}?`)) void act(() => deleteWebhook(h.id), "Webhook deleted"); }}>Delete</button>
            </div>
            {open === h.id && (
              <ul className="space-y-1 border-t border-[var(--border-color)] pt-2">
                {deliveries.length === 0 && <li className="text-[var(--text-muted)]">Nothing sent yet.</li>}
                {deliveries.map((d) => (
                  <li key={d.id} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono">{d.event_type}</span>
                    <span className={d.status === "dead" ? "text-[#EF4444]" : "text-[var(--text-secondary)]"}>{d.status}</span>
                    <span className="text-[var(--text-muted)]">{d.attempts} attempt(s){d.last_status_code ? ` · HTTP ${d.last_status_code}` : ""}{d.last_error ? ` · ${d.last_error}` : ""} · {relativeTime(d.created_at)}</span>
                    {(d.status === "dead" || d.status === "delivered") && (
                      <button className="button-secondary text-xs ml-auto" disabled={busy} onClick={() => void act(async () => { await redeliver(h.id, d.id); setDeliveries(await fetchDeliveries(h.id)); }, "Queued again")}>Redeliver</button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
        <div className="space-y-2 border-t border-[var(--border-color)] pt-3">
          <div className="flex flex-wrap gap-2">
            <input className={`${field} w-48`} placeholder="Name" aria-label="Webhook name" value={hook.name} onChange={(e) => setHook({ ...hook, name: e.target.value })} />
            <input className={`${field} flex-1 min-w-[16rem] font-mono`} placeholder="https://soar.example.com/forensiq" aria-label="Webhook URL" value={hook.url} onChange={(e) => setHook({ ...hook, url: e.target.value })} />
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px]">
            {eventTypes.filter((t) => t === "*" || t.endsWith(".*")).map((t) => (
              <label key={t} className="flex items-center gap-1"><input type="checkbox" checked={hook.events.includes(t)} onChange={() => setHook({ ...hook, events: toggle(hook.events, t) })} /> {t === "*" ? "everything" : t}</label>
            ))}
          </div>
          <button className="button-primary text-xs" disabled={busy || !hook.name.trim() || !hook.url.trim() || hook.events.length === 0}
            onClick={() => void act(async () => { const r = await createWebhook({ name: hook.name.trim(), url: hook.url.trim(), events: hook.events }); setReveal({ title: `Signing secret for ${r.name}`, value: r.secret }); setHook({ name: "", url: "", events: ["*"] }); })}>
            Add webhook
          </button>
          <p className="text-[11px] text-[var(--text-muted)]">Each request carries X-Forensiq-Timestamp and X-Forensiq-Signature (sha256 HMAC of &quot;timestamp.body&quot;). Failed deliveries retry up to 5 times over about 9 hours. Events can also be pulled from GET /api/v1/events.</p>
        </div>
      </section>

      <section className="card p-4 space-y-3" aria-label="API tokens">
        <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">API tokens (service accounts)</h2>
        {tokens === null && <Loader2 className="h-4 w-4 animate-spin" />}
        {tokens?.length === 0 && <p className="text-xs text-[var(--text-muted)]">No tokens yet.</p>}
        <ul className="space-y-1.5 text-xs">
          {tokens?.map((t) => (
            <li key={t.id} className="flex flex-wrap items-center gap-2 border border-[var(--border-color)] rounded px-2 py-1.5">
              <span className="font-semibold">{t.name}</span>
              <span className="font-mono text-[var(--text-muted)]">{t.prefix}…</span>
              <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded border border-[var(--border-color)]">{t.status}</span>
              <span className="text-[var(--text-muted)]">{t.scopes.join(", ")} · expires {new Date(t.expires_at).toLocaleDateString()}{t.last_used_at ? ` · used ${relativeTime(t.last_used_at)}` : " · never used"}</span>
              {t.status === "active" && (
                <button className="button-secondary text-xs ml-auto" disabled={busy} onClick={() => { if (window.confirm(`Revoke ${t.name}? Anything using it stops working immediately.`)) void act(() => revokeToken(t.id), "Token revoked"); }}>Revoke</button>
              )}
            </li>
          ))}
        </ul>
        <div className="space-y-2 border-t border-[var(--border-color)] pt-3">
          <div className="flex flex-wrap gap-2 items-center">
            <input className={`${field} w-56`} placeholder="Name (e.g. soar-playbooks)" aria-label="Token name" value={tok.name} onChange={(e) => setTok({ ...tok, name: e.target.value })} />
            <label className="text-[11px] text-[var(--text-muted)] flex items-center gap-1">Expires in <input className={`${field} w-16`} type="number" min={1} max={365} value={tok.days} onChange={(e) => setTok({ ...tok, days: e.target.value })} aria-label="Days until expiry" /> days</label>
          </div>
          <div className="grid gap-1 md:grid-cols-2 text-[11px]">
            {Object.entries(scopes).map(([name, description]) => (
              <label key={name} className="flex items-start gap-1.5"><input type="checkbox" className="mt-0.5" checked={tok.scopes.includes(name)} onChange={() => setTok({ ...tok, scopes: toggle(tok.scopes, name) })} /><span><span className="font-mono">{name}</span> <span className="text-[var(--text-muted)]">{description}</span></span></label>
            ))}
          </div>
          <button className="button-primary text-xs" disabled={busy || tok.name.trim().length < 2 || tok.scopes.length === 0}
            onClick={() => void act(async () => { const r = await createToken({ name: tok.name.trim(), scopes: tok.scopes, expires_in_days: Number(tok.days) || undefined }); setReveal({ title: `API token for ${r.name}`, value: r.token }); setTok({ name: "", scopes: [], days: "90" }); })}>
            Create token
          </button>
          <p className="text-[11px] text-[var(--text-muted)]">Send it as <code>Authorization: Bearer fsq_…</code>. A token acts as an analyst limited to its scopes: it can never approve or execute response actions, ingest, or manage users, tenants, webhooks or tokens.</p>
        </div>
      </section>
    </div>
  );
}
