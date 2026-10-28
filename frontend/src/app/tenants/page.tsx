"use client";

import { useCallback, useEffect, useState } from "react";
import { CircleAlert, Loader2 } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { relativeTime } from "@/lib/triage";
import {
  createTenant,
  fetchSettings,
  fetchTenants,
  saveSettings,
  setTenantStatus,
  testSiem,
  type SettingsUpdate,
  type TenantRow,
  type TenantSettings,
} from "@/lib/tenants";

const SOURCE_LABEL: Record<string, string> = { tenant: "this tenant", platform: "platform default", none: "not set" };

export default function TenantsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [tenants, setTenants] = useState<TenantRow[] | null>(null);
  const [target, setTarget] = useState<string | undefined>(undefined); // undefined = own tenant
  const [error, setError] = useState<string | null>(null);

  const loadTenants = useCallback(async () => {
    try {
      setTenants(await fetchTenants());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load tenants");
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    const t = setTimeout(() => void loadTenants(), 0);
    return () => clearTimeout(t);
  }, [isAdmin, loadTenants]);

  if (!isAdmin) {
    return <div className="page-state">Tenant administration is for administrators.</div>;
  }

  return (
    <div className="mx-auto flex max-w-[1200px] flex-col gap-4 pb-12">
      <header className="border-b border-[var(--border-color)] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">Tenants</h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Each tenant has its own SIEM connection, threat-intel keys and noise policy. Secrets are write-only: they are encrypted and never shown again.
        </p>
      </header>
      {error && (
        <div className="feedback-error" role="alert">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {tenants && <PlatformSection tenants={tenants} selected={target} onSelect={setTarget} onChanged={loadTenants} onError={setError} />}
      <SettingsForm key={target ?? "current"} orgId={target} onError={setError} onSaved={loadTenants} />
    </div>
  );
}

function PlatformSection(props: {
  tenants: TenantRow[];
  selected?: string;
  onSelect: (id?: string) => void;
  onChanged: () => Promise<void>;
  onError: (message: string | null) => void;
}) {
  const [form, setForm] = useState({ id: "", name: "", admin_email: "", admin_password: "" });
  const [busy, setBusy] = useState(false);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    props.onError(null);
    try {
      await fn();
      await props.onChanged();
    } catch (e) {
      props.onError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card p-4 space-y-3" aria-label="All tenants">
      <h2 className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">All tenants (platform administrators)</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs min-w-[640px]">
          <thead>
            <tr className="text-[11px] text-[var(--text-muted)] uppercase">
              <th className="py-1.5 pr-3">Tenant</th><th className="pr-3">Status</th><th className="pr-3">Users</th><th className="pr-3">SIEM</th><th className="pr-3">Last poll</th><th />
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-color)]">
            {props.tenants.map((t) => (
              <tr key={t.id}>
                <td className="py-2 pr-3"><span className="font-semibold">{t.name}</span> <span className="font-mono text-[var(--text-muted)]">{t.id}</span>{t.is_platform ? " (platform)" : ""}{!t.registered ? " · not registered" : ""}</td>
                <td className="pr-3">{t.status}</td>
                <td className="pr-3">{t.users}</td>
                <td className="pr-3">{t.siem_configured ? "connected" : "not set"}</td>
                <td className="pr-3" title={t.last_error ?? undefined}>{t.last_poll_at ? relativeTime(t.last_poll_at) : "never"}{t.last_error ? ` · error: ${t.last_error}` : ""}</td>
                <td className="py-2 flex gap-1.5 justify-end">
                  <button className="button-secondary text-xs" onClick={() => props.onSelect(t.is_platform ? undefined : t.id)}>Settings</button>
                  {!t.is_platform && t.registered && (
                    <button className="button-secondary text-xs" disabled={busy} onClick={() => void act(() => setTenantStatus(t.id, t.status === "active" ? "suspended" : "active"))}>
                      {t.status === "active" ? "Suspend" : "Reactivate"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid gap-2 md:grid-cols-5 items-end border-t border-[var(--border-color)] pt-3">
        <input className="field h-8 text-xs" placeholder="id (acme)" aria-label="Tenant id" value={form.id} onChange={(e) => setForm({ ...form, id: e.target.value })} />
        <input className="field h-8 text-xs" placeholder="Name" aria-label="Tenant name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input className="field h-8 text-xs" placeholder="First admin email" aria-label="Admin email" value={form.admin_email} onChange={(e) => setForm({ ...form, admin_email: e.target.value })} />
        <input className="field h-8 text-xs" type="password" placeholder="Password (12+ chars)" aria-label="Admin password" value={form.admin_password} onChange={(e) => setForm({ ...form, admin_password: e.target.value })} />
        <button
          className="button-primary text-xs"
          disabled={busy || !form.id || !form.name || !form.admin_email || form.admin_password.length < 12}
          onClick={() => void act(async () => { await createTenant(form); setForm({ id: "", name: "", admin_email: "", admin_password: "" }); })}
        >
          Create tenant
        </button>
      </div>
    </section>
  );
}

function SettingsForm({ orgId, onError, onSaved }: { orgId?: string; onError: (m: string | null) => void; onSaved: () => Promise<void> }) {
  const [settings, setSettings] = useState<TenantSettings | null>(null);
  const [f, setF] = useState({
    enabled: true, url: "", username: "", password: "", verify_ssl: true, detection_index: "", allowed: "", poll: "30",
    vt: "", abuse: "", benign: "", shared: "", reason: "",
  });
  const [busy, setBusy] = useState(false);
  const [info, setInfo] = useState<string | null>(null);

  const hydrate = useCallback((s: TenantSettings) => {
    setSettings(s);
    setF((prev) => ({
      ...prev, enabled: s.siem.enabled, url: s.siem.url, username: s.siem.username, verify_ssl: s.siem.verify_ssl,
      detection_index: s.siem.detection_index, allowed: s.siem.allowed_indexes.join(", "), poll: String(s.siem.poll_interval_seconds),
      password: "", vt: "", abuse: "", benign: (s.noise.benign_domains ?? []).join("\n"), shared: (s.noise.shared_hosting_domains ?? []).join("\n"),
    }));
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      fetchSettings(orgId).then(hydrate).catch((e) => onError(e instanceof Error ? e.message : "Unable to load settings"));
    }, 0);
    return () => clearTimeout(t);
  }, [orgId, hydrate, onError]);

  const lines = (text: string) => text.split(/[\n,]/).map((v) => v.trim()).filter(Boolean);

  const save = async (extra: Partial<SettingsUpdate> = {}) => {
    setBusy(true);
    onError(null);
    setInfo(null);
    try {
      const update: SettingsUpdate = {
        reason: f.reason.trim(),
        siem: {
          enabled: f.enabled, url: f.url.trim(), username: f.username.trim(), verify_ssl: f.verify_ssl, detection_index: f.detection_index.trim(),
          allowed_indexes: lines(f.allowed), poll_interval_seconds: Number(f.poll),
          ...(f.password ? { password: f.password } : {}),
        },
        threat_intel: { ...(f.vt ? { vt_api_key: f.vt } : {}), ...(f.abuse ? { abuseipdb_api_key: f.abuse } : {}) },
        noise: { benign_domains: lines(f.benign), shared_hosting_domains: lines(f.shared), suppress: settings?.noise.suppress ?? [] },
        ...extra,
      };
      const res = await saveSettings(update, orgId);
      hydrate(res.settings);
      setF((prev) => ({ ...prev, reason: "" }));
      setInfo(res.changed.length ? `Saved: ${res.changed.join(", ")}` : "Nothing changed");
      await onSaved();
    } catch (e) {
      onError(e instanceof Error ? e.message : "Unable to save");
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    onError(null);
    try {
      const r = await testSiem(orgId);
      setInfo(r.ok ? "SIEM connection works" : `SIEM connection failed: ${r.detail}`);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  if (!settings) return <div className="page-state"><Loader2 className="h-5 w-5 animate-spin" /></div>;
  const field = "field h-8 text-xs w-full";
  const label = "text-[11px] text-[var(--text-muted)]";

  return (
    <section className="card p-4 space-y-4" aria-label="Tenant settings">
      <h2 className="text-sm font-semibold text-[var(--text-primary)]">
        Settings for {settings.name} <span className="font-mono text-xs text-[var(--text-muted)]">{settings.id}</span>
      </h2>

      <fieldset className="space-y-2">
        <legend className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">SIEM (Splunk)</legend>
        <p className="text-xs text-[var(--text-muted)]">
          {settings.siem.configured ? `Connected using ${SOURCE_LABEL[settings.siem.source]} settings.` : "No SIEM is configured: nothing is polled and search returns only data already ingested."}
        </p>
        <div className="grid gap-3 md:grid-cols-3">
          <label className="space-y-1"><span className={label}>URL (https)</span><input className={field} value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://splunk.example.com:8089" /></label>
          <label className="space-y-1"><span className={label}>Username</span><input className={field} value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} autoComplete="off" /></label>
          <label className="space-y-1"><span className={label}>Password {settings.siem.password_set ? "(set; leave blank to keep)" : ""}</span><input className={field} type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" /></label>
          <label className="space-y-1"><span className={label}>Detection index</span><input className={field} value={f.detection_index} onChange={(e) => setF({ ...f, detection_index: e.target.value })} /></label>
          <label className="space-y-1"><span className={label}>Searchable indexes (comma separated)</span><input className={field} value={f.allowed} onChange={(e) => setF({ ...f, allowed: e.target.value })} /></label>
          <label className="space-y-1"><span className={label}>Poll every (seconds, 10-3600)</span><input className={field} type="number" min={10} max={3600} value={f.poll} onChange={(e) => setF({ ...f, poll: e.target.value })} /></label>
        </div>
        <div className="flex flex-wrap gap-4 text-xs">
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Poll this SIEM</label>
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={f.verify_ssl} onChange={(e) => setF({ ...f, verify_ssl: e.target.checked })} /> Verify TLS certificate</label>
          <button className="button-secondary text-xs" disabled={busy || !settings.siem.configured} onClick={() => void test()}>Test connection (saved settings)</button>
        </div>
      </fieldset>

      <fieldset className="space-y-2">
        <legend className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">Threat intelligence</legend>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="space-y-1">
            <span className={label}>VirusTotal API key: {settings.threat_intel.virustotal.configured ? `using ${SOURCE_LABEL[settings.threat_intel.virustotal.source]}` : "not set"}</span>
            <input className={field} type="password" value={f.vt} onChange={(e) => setF({ ...f, vt: e.target.value })} placeholder="Enter to replace" autoComplete="new-password" />
          </label>
          <label className="space-y-1">
            <span className={label}>AbuseIPDB API key: {settings.threat_intel.abuseipdb.configured ? `using ${SOURCE_LABEL[settings.threat_intel.abuseipdb.source]}` : "not set"}</span>
            <input className={field} type="password" value={f.abuse} onChange={(e) => setF({ ...f, abuse: e.target.value })} placeholder="Enter to replace" autoComplete="new-password" />
          </label>
        </div>
      </fieldset>

      <fieldset className="space-y-2">
        <legend className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">Noise policy ({settings.noise.source === "tenant" ? "this tenant's" : "platform default"})</legend>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="space-y-1"><span className={label}>Benign domains (one per line)</span><textarea className="field w-full text-xs font-mono" rows={4} value={f.benign} onChange={(e) => setF({ ...f, benign: e.target.value })} /></label>
          <label className="space-y-1"><span className={label}>Shared-hosting domains (never block whole domain)</span><textarea className="field w-full text-xs font-mono" rows={4} value={f.shared} onChange={(e) => setF({ ...f, shared: e.target.value })} /></label>
        </div>
        <p className="text-[11px] text-[var(--text-muted)]">Saving creates a tenant policy that replaces the platform default. Command-line suppression rules are managed through the API.</p>
        {settings.noise.source === "tenant" && (
          <button className="button-secondary text-xs" disabled={busy || f.reason.trim().length < 3} onClick={() => void save({ reset_noise: true, noise: undefined })}>Reset to platform policy</button>
        )}
      </fieldset>

      <div className="flex flex-wrap items-end gap-3 border-t border-[var(--border-color)] pt-3">
        <label className="flex-1 min-w-[16rem] space-y-1"><span className={label}>Reason for this change (audited)</span><input className={field} value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} /></label>
        <button className="button-primary text-xs" disabled={busy || f.reason.trim().length < 3} onClick={() => void save()}>
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Save settings"}
        </button>
      </div>
      {info && <p role="status" className="text-xs text-[var(--text-secondary)]">{info}</p>}
    </section>
  );
}
