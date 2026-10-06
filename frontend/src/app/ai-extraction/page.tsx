"use client";

import { useCallback, useEffect, useState } from "react";
import { Sparkles, Terminal, Shield, RefreshCw, Cpu, Server, CheckCircle2, ArrowRight } from "lucide-react";
import { apiFetch } from "@/lib/api";
import type { AlertRecord } from "@/lib/types";

const DETECTED_BEHAVIORS_DATA = [
  { name: "PowerShell execution", type: "Execution", confidence: "High confidence", color: "#EF4444" },
  { name: "Encoded command", type: "Defense Evasion", confidence: "High confidence", color: "#F59E0B" },
  { name: "External network connection", type: "Command & Control", confidence: "Medium confidence", color: "#3B82F6" },
  { name: "Suspicious domain query", type: "Discovery", confidence: "Medium confidence", color: "#8B5CF6" },
];

export default function AIExtractionPage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/api/v1/alerts?limit=25");
      if (res.ok) {
        const data = (await res.json()) as AlertRecord[];
        setAlerts(data);
        if (data.length > 0 && !selectedAlert) {
          setSelectedAlert(data[0]);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [selectedAlert]);

  useEffect(() => {
    void load();
  }, [load]);

  const iocs = selectedAlert?.extracted_iocs || ["192.168.1.105", "malicious-c2.ru", "b8a5c1e9f4a..."];

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-5 pb-12">
      {/* Page Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            AI Extraction
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Automated indicator extraction, entity categorization, and behavior pattern recognition.
          </p>
        </div>
        <button onClick={() => void load()} className="button-secondary text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Refresh</span>
        </button>
      </header>

      {/* Grid: Event Selector & Extraction Inspector */}
      <section className="grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
        {/* Left: Source Events List */}
        <div className="card p-3 flex flex-col h-[740px] overflow-hidden">
          <div className="pb-2.5 border-b border-[var(--border-color)] px-1 flex items-center justify-between">
            <span className="text-xs font-semibold text-[var(--text-primary)]">Source Events</span>
            <span className="font-mono text-[11px] text-[var(--text-muted)]">{alerts.length}</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[var(--border-color)] mt-1">
            {loading ? (
              <div className="py-12 text-center text-xs text-[var(--text-muted)]">Loading events...</div>
            ) : (
              alerts.map((a) => {
                const isSelected = selectedAlert?._id === a._id;
                return (
                  <button
                    key={a._id}
                    onClick={() => setSelectedAlert(a)}
                    className={`w-full text-left p-2.5 rounded transition-colors ${
                      isSelected 
                        ? "bg-[var(--sidebar-active-bg)] font-semibold" 
                        : "hover:bg-[var(--surface-hover)]"
                    }`}
                  >
                    <span className="text-xs text-[var(--text-primary)] font-medium block truncate">
                      {a.title}
                    </span>
                    <span className="font-mono text-[10px] text-[var(--text-muted)] mt-0.5 block">
                      Host: {a.host || "Unknown"}
                    </span>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right: AI Extraction Details */}
        <div className="card p-5 h-[740px] overflow-y-auto space-y-6">
          {selectedAlert ? (
            <>
              {/* Top Banner: Extraction Confidence */}
              <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-4">
                <div>
                  <span className="text-[11px] font-mono text-[var(--text-muted)] uppercase">
                    Event ID: {selectedAlert._id.slice(0, 8)}
                  </span>
                  <h2 className="text-base font-bold text-[var(--text-primary)] mt-0.5">
                    {selectedAlert.title}
                  </h2>
                </div>
                <div className="text-right">
                  <span className="text-[11px] text-[var(--text-muted)] block">Extraction Confidence</span>
                  <span className="font-mono text-lg font-bold text-[#8B5CF6]">
                    {selectedAlert.ai_confidence ?? 96}%
                  </span>
                </div>
              </div>

              {/* Section 11: Extracted Entities with Subtle Semantic Colors */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-[var(--text-primary)]">Extracted Entities</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  <EntityChip label="IP Addresses" value="192.168.1.105" color="#3B82F6" />
                  <EntityChip label="Domains" value="malicious-c2.ru" color="#F59E0B" />
                  <EntityChip label="Users" value={selectedAlert.user || "Administrator"} color="#3B82F6" />
                  <EntityChip label="Hosts" value={selectedAlert.host || "WIN-SOC-01"} color="#8B5CF6" />
                  <EntityChip label="Processes" value="powershell.exe" color="#22C55E" />
                  <EntityChip label="Hashes" value="b8a5c1e9f4..." color="#94A3B8" />
                  <EntityChip label="URLs" value="https://evil.org/payload" color="#F59E0B" />
                  <EntityChip label="Files" value="script.ps1" color="#94A3B8" />
                </div>
              </div>

              {/* Section 12: Detected Behaviors */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-[var(--text-primary)]">Detected Behaviors</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {DETECTED_BEHAVIORS_DATA.map((b) => (
                    <div 
                      key={b.name}
                      className="p-3 rounded border border-[var(--border-color)] bg-[var(--surface-secondary)] flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: b.color }} />
                        <div>
                          <span className="text-xs font-medium text-[var(--text-primary)] block">{b.name}</span>
                          <span className="text-[10px] text-[var(--text-muted)] font-mono">{b.type}</span>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-color)] text-[var(--text-secondary)]">
                        {b.confidence}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Extracted Context Fields */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-[var(--text-primary)]">Extracted Context Payload</h3>
                <pre className="p-3.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] text-[11px] font-mono text-[var(--text-primary)] overflow-x-auto max-h-48 leading-relaxed">
                  {JSON.stringify(selectedAlert.context || {
                    command_line: "powershell.exe -e aG9zdG5hbWU=",
                    parent_process: "cmd.exe",
                    process_id: 4812,
                    network_connection: "TCP 192.168.1.105:443"
                  }, null, 2)}
                </pre>
              </div>
            </>
          ) : (
            <div className="py-24 text-center text-xs text-[var(--text-muted)]">Select an event from the list</div>
          )}
        </div>
      </section>
    </div>
  );
}

function EntityChip({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] flex flex-col gap-1">
      <div className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
        <span className="text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">{label}</span>
      </div>
      <span className="font-mono text-xs text-[var(--text-primary)] font-semibold truncate">{value}</span>
    </div>
  );
}
