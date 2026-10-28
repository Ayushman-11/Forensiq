"use client";

import { useEffect, useState } from "react";
import { Server, User, Cpu, ShieldCheck, CircleAlert, Info } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { roleLabel } from "@/lib/roles";
import { apiFetch } from "@/lib/api";
import { STATE_COLOR, STATE_LABEL, useSystemHealth, type ComponentState } from "@/lib/health";

type EffectiveConfig = {
  siem: { url: string; verify_ssl: boolean; detection_index: string; allowed_indexes: string[]; poll_interval_seconds: number };
  llm: { configured: boolean; provider: string; model: string };
  threat_intel: {
    virustotal_configured: boolean;
    abuseipdb_configured: boolean;
    vt_malicious_min_engines: number;
    abuseipdb_malicious_min_score: number;
    abuseipdb_suspicious_min_score: number;
    cache_ttl_hours: number;
  };
  investigation: { auto_concurrency: number };
};

export default function AdministrationPage() {
  const { user } = useAuth();
  const { health } = useSystemHealth();
  const [config, setConfig] = useState<EffectiveConfig | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiFetch("/api/v1/dashboard/config");
        if (res.status === 403) throw new Error("Only administrators can view the platform configuration.");
        if (!res.ok) throw new Error("Unable to load configuration.");
        const body = (await res.json()) as EffectiveConfig;
        if (!cancelled) setConfig(body);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unable to load configuration.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-5 pb-12">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">Administration</h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Effective platform configuration and live integration status.
          </p>
        </div>
      </header>

      <div className="flex items-start gap-2 rounded border border-[var(--border-color)] bg-[var(--surface-secondary)] px-3.5 py-2.5 text-xs text-[var(--text-secondary)]">
        <Info className="h-4 w-4 shrink-0 mt-0.5" />
        <span>
          Read-only. Settings are set in <code className="font-mono">backend/.env</code> and take effect after an API restart.
        </span>
      </div>

      {error && (
        <div className="feedback-error">
          <CircleAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Section icon={<Server className="w-4 h-4" />} title="SIEM (Splunk)">
          <Row label="Connection" state={health?.siem.state} value={health?.siem.detail} />
          <Row label="Management URL" value={config?.siem.url} mono />
          <Row label="TLS verification" value={config ? (config.siem.verify_ssl ? "On" : "Off") : undefined} warn={config ? !config.siem.verify_ssl : false} />
          <Row label="Detection index" value={config?.siem.detection_index} mono />
          <Row label="Searchable indexes" value={config?.siem.allowed_indexes.join(", ")} mono />
          <Row label="Ingestion" state={health?.ingestion.state} value={health?.ingestion.detail} />
          <Row label="Poll interval" value={config ? `${config.siem.poll_interval_seconds}s` : undefined} />
        </Section>

        <Section icon={<Cpu className="w-4 h-4" />} title="Assessment engine">
          <Row label="Status" state={health?.ai.state} value={health?.ai.detail} />
          <Row label="Provider / model" value={config ? `${config.llm.provider} · ${config.llm.model}` : undefined} mono />
          <Row label="LLM key" value={config ? (config.llm.configured ? "Configured" : "Not configured") : undefined} warn={config ? !config.llm.configured : false} />
          <Row label="Auto-investigation concurrency" value={config?.investigation.auto_concurrency?.toString()} />
        </Section>

        <Section icon={<ShieldCheck className="w-4 h-4" />} title="Threat intelligence">
          {(health?.threat_intel.feeds ?? []).map((f) => (
            <Row
              key={f.feed}
              label={f.feed}
              state={f.state}
              value={f.recent_errors ? `${f.recent_errors} errors in recent investigations` : undefined}
            />
          ))}
          <Row label="VirusTotal: malicious at" value={config ? `≥ ${config.threat_intel.vt_malicious_min_engines} engines` : undefined} />
          <Row
            label="AbuseIPDB: suspicious / malicious at"
            value={config ? `≥ ${config.threat_intel.abuseipdb_suspicious_min_score} / ≥ ${config.threat_intel.abuseipdb_malicious_min_score}` : undefined}
          />
          <Row label="Verdict cache TTL" value={config ? `${config.threat_intel.cache_ttl_hours}h` : undefined} />
        </Section>

        <Section icon={<User className="w-4 h-4" />} title="Signed-in user">
          <Row label="Email" value={user?.email} />
          <Row label="Role" value={user ? roleLabel(user.role) : undefined} />
          <Row label="User ID" value={user?.sub} mono />
        </Section>
      </div>
    </div>
  );
}

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="card p-4 space-y-3">
      <div className="flex items-center gap-2 border-b border-[var(--border-color)] pb-2.5 text-[var(--text-muted)]">
        {icon}
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h2>
      </div>
      <div className="space-y-2.5 text-xs">{children}</div>
    </div>
  );
}

function Row({ label, value, state, mono, warn }: { label: string; value?: string; state?: ComponentState; mono?: boolean; warn?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-[var(--text-secondary)] shrink-0">{label}</span>
      <span className={`text-right min-w-0 break-words ${mono ? "font-mono text-[11px]" : ""} ${warn ? "text-[#F59E0B]" : "text-[var(--text-primary)]"}`}>
        {state && (
          <span className="inline-flex items-center gap-1.5 mr-2 font-mono text-[11px]">
            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: STATE_COLOR[state] }} />
            {STATE_LABEL[state]}
          </span>
        )}
        {value ?? (state ? "" : "—")}
      </span>
    </div>
  );
}
