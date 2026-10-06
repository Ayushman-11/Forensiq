"use client";

import { useState } from "react";
import { Server, User, CheckCircle2, Cpu } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { roleLabel } from "@/lib/roles";

export default function AdministrationPage() {
  const { user } = useAuth();
  const [splunkHost, setSplunkHost] = useState("localhost");
  const [splunkPort, setSplunkPort] = useState("8089");
  const [aiModel, setAiModel] = useState("grok-beta");
  const [cacheTtl, setCacheTtl] = useState("86400");
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-5 pb-12">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Administration
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            System configuration · SIEM connection, AI model options, and user role management.
          </p>
        </div>
      </header>

      {saved && (
        <div className="flex items-center gap-2 rounded border border-[#22C55E]/30 bg-[#22C55E]/10 px-3.5 py-2 text-xs font-medium text-[#22C55E]">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>System configuration updated successfully.</span>
        </div>
      )}

      {/* Grid Section */}
      <form onSubmit={handleSave} className="grid gap-5 lg:grid-cols-2">
        {/* SIEM Splunk Connection Settings */}
        <div className="card p-4 space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-color)] pb-2.5">
            <Server className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">SIEM Splunk Connection</h2>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">Splunk Host / Management URL</label>
              <input 
                type="text" 
                value={splunkHost} 
                onChange={(e) => setSplunkHost(e.target.value)}
                className="field font-mono" 
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">Management Port (REST API)</label>
              <input 
                type="text" 
                value={splunkPort} 
                onChange={(e) => setSplunkPort(e.target.value)}
                className="field font-mono" 
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[var(--border-color)] text-xs">
              <span className="text-[var(--text-secondary)]">Authentication Status</span>
              <span className="font-mono text-[11px] font-semibold text-[#22C55E] flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" /> Authenticated
              </span>
            </div>
          </div>
        </div>

        {/* AI Agent Engine Settings */}
        <div className="card p-4 space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-color)] pb-2.5">
            <Cpu className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">AI Agent Pipeline Config</h2>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">LLM Provider & Model</label>
              <select 
                value={aiModel} 
                onChange={(e) => setAiModel(e.target.value)}
                className="field font-mono cursor-pointer"
              >
                <option value="grok-beta">xAI Grok-Beta (Default)</option>
                <option value="gpt-4o">OpenAI GPT-4o</option>
                <option value="claude-3-5-sonnet">Anthropic Claude 3.5 Sonnet</option>
              </select>
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">Threat Cache TTL (Seconds)</label>
              <input 
                type="text" 
                value={cacheTtl} 
                onChange={(e) => setCacheTtl(e.target.value)}
                className="field font-mono" 
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[var(--border-color)] text-xs">
              <span className="text-[var(--text-secondary)]">LangGraph Agent Graph</span>
              <span className="font-mono text-[11px] font-semibold text-[#8B5CF6]">7 Nodes Loaded</span>
            </div>
          </div>
        </div>

        {/* Current User & Role Profile */}
        <div className="card p-4 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-2.5">
            <div className="flex items-center gap-2">
              <User className="w-4 h-4 text-[var(--text-muted)]" />
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">Active User Profile</h2>
            </div>
            <span className="font-mono text-xs text-[var(--text-muted)]">Multi-Tenant RBAC</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
              <span className="text-[11px] text-[var(--text-muted)] block">Email</span>
              <span className="font-semibold text-[var(--text-primary)]">{user?.email || "admin@forensiq.ai"}</span>
            </div>
            <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
              <span className="text-[11px] text-[var(--text-muted)] block">Role</span>
              <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">{user ? roleLabel(user.role) : "SPLUNK ADMIN"}</span>
            </div>
            <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)]">
              <span className="text-[11px] text-[var(--text-muted)] block">User ID (Sub)</span>
              <span className="font-mono text-xs text-[var(--text-primary)] truncate">{user?.sub || "user-001"}</span>
            </div>
          </div>

          <div className="flex justify-end pt-3 border-t border-[var(--border-color)]">
            <button type="submit" className="button-primary text-xs">
              Save Configuration
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
