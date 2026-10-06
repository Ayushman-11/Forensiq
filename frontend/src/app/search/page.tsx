"use client";

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Terminal, 
  Search, 
  Loader2, 
  AlertCircle, 
  Clock, 
  Code, 
  User, 
  Play, 
  Copy, 
  Check, 
  ChevronRight, 
  ChevronDown, 
  Download, 
  Sparkles,
  Server
} from 'lucide-react';
import { apiFetch } from '@/lib/api';

const QUICK_QUERIES = [
  {
    label: 'Failed Windows Logins (4625)',
    query: 'search EventCode=4625',
    category: 'Authentication'
  },
  {
    label: 'Process Creation (Sysmon 1)',
    query: 'search EventCode=1 | head 50',
    category: 'Execution'
  },
  {
    label: 'Network Connections (Sysmon 3)',
    query: 'search EventCode=3 | head 50',
    category: 'Network'
  },
  {
    label: 'Latest Windows Telemetry',
    query: 'search | head 50',
    category: 'Discovery'
  }
];

const TIME_RANGES = [
  { label: 'Past 24 Hours', value: '-24h' },
  { label: 'Past 7 Days', value: '-7d' },
  { label: 'Past 1 Hour', value: '-1h' },
  { label: 'Past 15 Minutes', value: '-15m' },
];

type SearchEvent = { 
  timestamp?: string; 
  hostname?: string; 
  provider?: string; 
  event_id?: string; 
  command_line?: string; 
  process_name?: string; 
  process_path?: string;
  user?: string;
  domain?: string;
  source_ip?: string;
  destination_ip?: string;
  severity?: string;
  mitre_technique_id?: string;
  raw_payload?: Record<string, unknown>; 
};

export default function SearchPage() {
  const [query, setQuery] = useState('search | head 50');
  const [timeRange, setTimeRange] = useState('-24h');
  const [events, setEvents] = useState<SearchEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTime, setSearchTime] = useState<number | null>(null);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleSearch = async (q?: string, t?: string) => {
    const searchQuery = q ?? query;
    const selectedTime = t ?? timeRange;
    if (!searchQuery.trim()) return;
    if (q) setQuery(q);

    setLoading(true);
    setError(null);
    setExpandedRow(null);
    const startTime = performance.now();

    try {
      const res = await apiFetch('/api/v1/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: searchQuery,
          earliest_time: selectedTime,
          latest_time: 'now',
          limit: 150
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setEvents(data.events || []);
      setSearchTime(Math.round(performance.now() - startTime));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'An error occurred while executing SPL search against SIEM');
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (dateStr?: string) => {
    if (!dateStr) return "-";
    try {
      const d = new Date(dateStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: 'numeric' });
    } catch { 
      return dateStr; 
    }
  };

  const copyPayload = (payload: unknown, idx: number) => {
    void navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const exportJSON = () => {
    if (!events.length) return;
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `splunk_telemetry_export_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-5 max-w-[1520px] mx-auto pb-12">
      {/* Top Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Raw Logs (SPL Search)
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Execute direct Splunk Search Processing Language (SPL) queries to inspect endpoint and security log events.
          </p>
        </div>

        {events.length > 0 && (
          <button
            onClick={exportJSON}
            className="button-secondary text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export ({events.length})</span>
          </button>
        )}
      </header>

      {/* Quick SPL Presets */}
      <div className="card p-3">
        <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider block mb-2">
          Recommended SPL Presets
        </span>
        <div className="flex flex-wrap gap-2">
          {QUICK_QUERIES.map((q) => (
            <button
              key={q.label}
              onClick={() => handleSearch(q.query)}
              className="flex items-center gap-2 px-2.5 py-1.5 rounded border border-[var(--border-color)] bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] text-xs text-[var(--text-primary)] transition-colors cursor-pointer"
            >
              <span className="font-mono text-[9px] uppercase px-1 py-0.2 rounded bg-[var(--surface-elevated)] text-[var(--text-muted)] border border-[var(--border-color)]">
                {q.category}
              </span>
              <span>{q.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Query Search Console */}
      <div className="card p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-[var(--text-primary)] font-mono">SPL Console</span>
          <select
            value={timeRange}
            onChange={(e) => {
              setTimeRange(e.target.value);
              void handleSearch(query, e.target.value);
            }}
            className="field h-7 text-xs font-mono cursor-pointer"
          >
            {TIME_RANGES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col sm:flex-row gap-2">
          <div className="flex-1 bg-[var(--surface-secondary)] border border-[var(--border-color)] rounded px-3 py-2 flex items-center gap-2">
            <span className="font-mono text-xs text-[var(--text-muted)]">&gt;_</span>
            <input
              type="text"
              placeholder='search EventCode=4625'
              className="w-full bg-transparent border-none outline-none font-mono text-xs text-[var(--text-primary)]"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
          </div>

          <button
            onClick={() => handleSearch()}
            disabled={loading}
            className="button-primary text-xs shrink-0"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            <span>{loading ? "Executing..." : "Run Search"}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="feedback-error">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View Table */}
      <div className="card overflow-hidden">
        <div className="p-3 border-b border-[var(--border-color)] bg-[var(--surface-secondary)] flex justify-between items-center text-xs">
          <span className="font-semibold text-[var(--text-primary)] font-mono">
            Event Results ({events.length})
          </span>
          {searchTime !== null && (
            <span className="font-mono text-[11px] text-[var(--text-muted)]">
              Query execution: {(searchTime / 1000).toFixed(2)}s
            </span>
          )}
        </div>

        <div className="overflow-x-auto font-mono text-xs">
          {loading ? (
            <div className="py-16 text-center text-[var(--text-muted)]">
              <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
              <span>Streaming events from SIEM...</span>
            </div>
          ) : events.length === 0 ? (
            <div className="py-16 text-center text-[var(--text-muted)]">
              No telemetry events returned for query.
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[var(--border-color)] bg-[var(--surface-primary)] text-[10px] text-[var(--text-muted)] uppercase">
                  <th className="py-2.5 px-3 w-10 text-center">#</th>
                  <th className="py-2.5 px-3 w-40">Time</th>
                  <th className="py-2.5 px-3 w-44">Host / User</th>
                  <th className="py-2.5 px-3 w-32">Provider</th>
                  <th className="py-2.5 px-3 w-24">Event ID</th>
                  <th className="py-2.5 px-3">Telemetry Payload / Command</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-color)]">
                {events.map((ev, i) => {
                  const isExpanded = expandedRow === i;
                  return (
                    <React.Fragment key={i}>
                      <tr 
                        onClick={() => setExpandedRow(isExpanded ? null : i)}
                        className="hover:bg-[var(--surface-hover)] cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-3 text-center text-[var(--text-muted)]">
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5 mx-auto" /> : <ChevronRight className="w-3.5 h-3.5 mx-auto" />}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)] whitespace-nowrap">
                          {formatTime(ev.timestamp)}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-primary)] font-semibold">
                          {ev.hostname || "Unknown"}
                          {ev.user && <span className="text-[var(--text-muted)] block font-normal text-[11px]">{ev.user}</span>}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)]">
                          {ev.provider || "Sysmon"}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)]">
                          {ev.event_id || "-"}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-primary)] truncate max-w-xl">
                          {ev.command_line || ev.process_name || JSON.stringify(ev.raw_payload || {}).slice(0, 100)}
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-[var(--surface-secondary)]">
                          <td colSpan={6} className="p-4 border-b border-[var(--border-color)]">
                            <div className="space-y-3">
                              <div className="flex justify-between items-center text-xs">
                                <span className="font-semibold text-[var(--text-primary)]">Raw Telemetry Payload</span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    copyPayload(ev, i);
                                  }}
                                  className="button-secondary text-[11px] py-1 px-2"
                                >
                                  {copiedIndex === i ? "Copied!" : "Copy JSON"}
                                </button>
                              </div>
                              <pre className="p-3 rounded bg-[var(--bg-app)] border border-[var(--border-color)] text-[11px] text-[var(--text-primary)] overflow-x-auto max-h-60 leading-relaxed">
                                {JSON.stringify(ev.raw_payload || ev, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
