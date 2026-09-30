"use client";

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Terminal, 
  Search, 
  Loader2, 
  AlertCircle, 
  Clock, 
  Monitor, 
  Code, 
  Hash, 
  ShieldAlert, 
  User, 
  Play, 
  Copy, 
  Check, 
  ChevronRight, 
  ChevronDown, 
  Filter, 
  Download, 
  RefreshCw,
  Sparkles,
  Server
} from 'lucide-react';
import { apiFetch } from '@/lib/api';

const QUICK_QUERIES = [
  { 
    label: 'Failed Windows Logins (4625)', 
    query: 'search index=windows source="XmlWinEventLog:Security" EventCode=4625',
    category: 'Authentication'
  },
  { 
    label: 'PowerShell Execution (Sysmon 1)', 
    query: 'search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell*"',
    category: 'Execution'
  },
  { 
    label: 'Outbound Network Conns (Sysmon 3)', 
    query: 'search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3',
    category: 'Network'
  },
  { 
    label: 'DNS Query Telemetry (Sysmon 22)', 
    query: 'search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22',
    category: 'Discovery'
  },
  {
    label: 'High Severity Security Detections',
    query: 'search index=windows severity="high" OR severity="critical"',
    category: 'Threats'
  }
];

const TIME_RANGES = [
  { label: 'Past 15 Minutes', value: '-15m' },
  { label: 'Past 1 Hour', value: '-1h' },
  { label: 'Past 24 Hours', value: '-24h' },
  { label: 'Past 7 Days', value: '-7d' },
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
  const [query, setQuery] = useState('search index=windows EventCode=4625');
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
      const res = await apiFetch('/api/v1/search/search', {
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
    <div className="flex flex-col gap-6 max-w-[1700px] mx-auto pb-12">
      {/* Top Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1E2E48] pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="dot-live" />
            <p className="label text-cyan-400 font-mono tracking-widest text-xs">
              SIEM INVESTIGATION ENGINE / SPL SEARCH
            </p>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
            <Terminal className="w-8 h-8 text-cyan-400" />
            Raw Telemetry Explorer
          </h1>
          <p className="mt-1 text-sm text-slate-300">
            Execute direct Splunk Search Processing Language (SPL) queries to inspect low-level endpoint and security log events.
          </p>
        </div>

        {events.length > 0 && (
          <div className="flex items-center gap-3">
            <button
              onClick={exportJSON}
              className="button-secondary cursor-pointer py-2.5 px-4 text-sm font-semibold"
              title="Download results as structured JSON"
            >
              <Download className="w-4 h-4 text-cyan-400" />
              <span>Export Telemetry ({events.length})</span>
            </button>
          </div>
        )}
      </header>

      {/* Quick SPL Presets */}
      <div className="card p-4 border-[#1E2E48]">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <p className="label text-slate-300 font-bold text-xs">Recommended SPL Presets</p>
        </div>
        <div className="flex flex-wrap gap-2.5">
          {QUICK_QUERIES.map((q) => (
            <button
              key={q.label}
              onClick={() => handleSearch(q.query)}
              className="group flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#111C2E] border border-[#20304C] hover:border-cyan-500/50 hover:bg-[#16253D] transition-all cursor-pointer text-left"
            >
              <span className="font-mono text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-[#182944] text-cyan-300 border border-cyan-500/30">
                {q.category}
              </span>
              <span className="text-xs font-semibold text-slate-200 group-hover:text-white transition-colors">
                {q.label}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Query Search Console */}
      <div className="card p-5 border-[#1E2E48] shadow-2xl flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">SPL Search Bar</span>
          </div>
          
          {/* Time range selector */}
          <div className="flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={timeRange}
              onChange={(e) => {
                setTimeRange(e.target.value);
                void handleSearch(query, e.target.value);
              }}
              className="bg-[#121B2C] border border-[#223554] text-slate-200 text-xs font-medium rounded-lg px-2.5 py-1.5 focus:border-cyan-500 focus:outline-none cursor-pointer"
            >
              {TIME_RANGES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Input Bar */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 bg-[#090F19] border border-[#1E2E48] rounded-xl px-4 py-3 flex items-center gap-3 focus-within:border-cyan-500/80 focus-within:ring-2 focus-within:ring-cyan-500/20 transition-all shadow-inner">
            <span className="font-mono font-bold text-cyan-400 select-none text-base">&gt;_</span>
            <input
              type="text"
              placeholder='search index=windows EventCode=4625 | stats count by IpAddress'
              className="w-full bg-transparent border-none outline-none font-mono text-sm sm:text-base text-cyan-300 placeholder:text-slate-500 font-medium"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
          </div>

          <button
            onClick={() => handleSearch()}
            disabled={loading}
            className="button-primary cursor-pointer px-6 py-3 text-sm font-bold tracking-wide shrink-0 justify-center"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-amber-300" />
                <span>Executing SPL…</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-cyan-400 text-cyan-400" />
                <span>Run Query</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Message */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="feedback-error"
          >
            <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
            <div className="flex-1">
              <p className="font-bold text-rose-200">Query Failed</p>
              <p className="text-xs text-rose-300/90 mt-0.5">{error}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results View Container */}
      <div className="card border-[#1E2E48] overflow-hidden flex flex-col min-h-[500px] shadow-xl">
        {/* Results Header Bar */}
        <div className="p-4 border-b border-[#1A2942] bg-[#0C1424] flex flex-wrap justify-between items-center gap-3">
          <div className="flex items-center gap-3">
            <h3 className="font-bold text-sm text-white flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Event Results
              {events.length > 0 && (
                <span className="px-2.5 py-0.5 rounded-full bg-[#16253E] border border-[#22385C] text-xs font-mono font-bold text-cyan-300">
                  {events.length} records
                </span>
              )}
            </h3>

            {searchTime !== null && (
              <span className="text-xs text-slate-400 font-mono font-medium flex items-center gap-1.5 ml-2 border-l border-[#1F304B] pl-3">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                Execution: <strong className="text-slate-200">{(searchTime / 1000).toFixed(2)}s</strong>
              </span>
            )}
          </div>

          {events.length > 0 && (
            <span className="text-xs text-slate-400 font-medium">
              Click any row to expand full JSON telemetry & execution context
            </span>
          )}
        </div>

        {/* Results Body */}
        <div className="overflow-x-auto flex-1">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-80 gap-3 text-slate-400">
              <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
              <p className="font-mono text-sm font-semibold text-slate-300">Streaming Telemetry from Splunk Enterprise…</p>
            </div>
          ) : events.length === 0 && !error ? (
            <div className="flex flex-col items-center justify-center h-80 gap-3 text-slate-400 p-8 text-center">
              <div className="w-14 h-14 rounded-2xl bg-[#121B2C] border border-[#22354E] flex items-center justify-center text-cyan-400 shadow-lg">
                <Terminal className="w-7 h-7" />
              </div>
              <p className="text-base font-bold text-white">No Telemetry Events Loaded</p>
              <p className="text-xs sm:text-sm text-slate-400 max-w-md leading-relaxed">
                Choose one of the quick presets above or enter an SPL search string to query indexed host and process logs.
              </p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-[#0A101C] border-b border-[#1E2E48] z-10">
                <tr className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">
                  <th className="py-3 px-4 w-12 text-center">#</th>
                  <th className="py-3 px-4 w-44">Time</th>
                  <th className="py-3 px-4 w-48">Host & User</th>
                  <th className="py-3 px-4 w-36">Provider</th>
                  <th className="py-3 px-4 w-28">Event ID</th>
                  <th className="py-3 px-4">Telemetry Payload / Command</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152238] font-mono text-xs">
                {events.map((ev, i) => {
                  const isExpanded = expandedRow === i;
                  return (
                    <React.Fragment key={i}>
                      <tr
                        onClick={() => setExpandedRow(isExpanded ? null : i)}
                        className={`cursor-pointer transition-colors ${
                          isExpanded 
                            ? 'bg-[#15233B]' 
                            : 'hover:bg-[#101A2C] bg-transparent'
                        }`}
                      >
                        <td className="py-3 px-4 text-center text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-cyan-400 mx-auto" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-slate-500 mx-auto" />
                          )}
                        </td>
                        
                        {/* Time */}
                        <td className="py-3 px-4 text-slate-300 font-semibold whitespace-nowrap">
                          {formatTime(ev.timestamp)}
                        </td>

                        {/* Host & User */}
                        <td className="py-3 px-4">
                          <div className="flex flex-col gap-0.5">
                            <span className="font-bold text-white flex items-center gap-1.5">
                              <Server className="w-3 h-3 text-cyan-400 shrink-0" />
                              {ev.hostname || 'Unknown'}
                            </span>
                            {ev.user && (
                              <span className="text-[11px] text-slate-400 flex items-center gap-1 font-sans">
                                <User className="w-2.5 h-2.5 text-slate-500" />
                                {ev.user}
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Provider */}
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className="text-[11px] px-2 py-0.5 rounded bg-[#16233B] text-cyan-300 border border-[#23354E] font-bold uppercase">
                            {ev.provider || 'Sysmon'}
                          </span>
                        </td>

                        {/* Event ID */}
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className="text-xs bg-[#121B2C] border border-[#23354E] px-2 py-0.5 rounded font-bold text-amber-300">
                            ID {ev.event_id || '-'}
                          </span>
                        </td>

                        {/* Command Line / Summary */}
                        <td className="py-3 px-4">
                          <div className="truncate max-w-2xl text-slate-200 font-medium">
                            {ev.command_line ? (
                              <span className="text-cyan-200">{ev.command_line}</span>
                            ) : ev.process_name ? (
                              <span className="text-slate-300">Process: {ev.process_name}</span>
                            ) : (
                              <span className="text-slate-400">{JSON.stringify(ev.raw_payload || {}).slice(0, 140)}</span>
                            )}
                          </div>
                        </td>
                      </tr>

                      {/* Expanded Detail Panel */}
                      {isExpanded && (
                        <tr className="bg-[#090F1A]">
                          <td colSpan={6} className="p-4 border-b border-[#1E2E48]">
                            <div className="rounded-xl bg-[#070B13] border border-[#1C2C45] p-4 flex flex-col gap-4">
                              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#162339] pb-3">
                                <div className="flex items-center gap-3">
                                  <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-sans">
                                    Raw Event Telemetry Inspector
                                  </span>
                                  {ev.event_id && (
                                    <span className="text-xs font-mono font-bold text-amber-300 px-2 py-0.5 rounded bg-[#16233B] border border-amber-500/30">
                                      Event ID: {ev.event_id}
                                    </span>
                                  )}
                                  {ev.severity && (
                                    <span className="text-xs font-mono font-bold uppercase text-slate-300 px-2 py-0.5 rounded bg-[#16233B] border border-[#243754]">
                                      Severity: {ev.severity}
                                    </span>
                                  )}
                                </div>

                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    copyPayload(ev, i);
                                  }}
                                  className="button-secondary py-1.5 px-3 text-xs flex items-center gap-1.5 cursor-pointer"
                                >
                                  {copiedIndex === i ? (
                                    <>
                                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                                      <span className="text-emerald-300">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3.5 h-3.5 text-slate-400" />
                                      <span>Copy Raw JSON</span>
                                    </>
                                  )}
                                </button>
                              </div>

                              {/* Structured Metadata Grid */}
                              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-sans">
                                <div className="p-2.5 rounded-lg bg-[#0F1726] border border-[#1A2840]">
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Timestamp</p>
                                  <p className="font-mono text-slate-200 mt-0.5">{ev.timestamp || "-"}</p>
                                </div>
                                <div className="p-2.5 rounded-lg bg-[#0F1726] border border-[#1A2840]">
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Host / System</p>
                                  <p className="font-mono text-slate-200 mt-0.5">{ev.hostname || "-"}</p>
                                </div>
                                <div className="p-2.5 rounded-lg bg-[#0F1726] border border-[#1A2840]">
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">User / Account</p>
                                  <p className="font-mono text-slate-200 mt-0.5">{ev.user || "SYSTEM"}</p>
                                </div>
                                <div className="p-2.5 rounded-lg bg-[#0F1726] border border-[#1A2840]">
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Process Image</p>
                                  <p className="font-mono text-slate-200 mt-0.5 truncate">{ev.process_name || ev.process_path || "-"}</p>
                                </div>
                              </div>

                              {/* Command Line Section */}
                              {ev.command_line && (
                                <div className="p-3 rounded-lg bg-[#0F1726] border border-[#1A2840]">
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-sans mb-1">
                                    Execution Command Line
                                  </p>
                                  <code className="text-xs text-cyan-300 font-mono break-all block whitespace-pre-wrap">
                                    {ev.command_line}
                                  </code>
                                </div>
                              )}

                              {/* Raw JSON viewer */}
                              <div>
                                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-sans mb-1.5">
                                  Complete Event Payload
                                </p>
                                <pre className="p-3.5 rounded-lg bg-[#05080E] border border-[#152238] text-[11px] font-mono text-slate-300 overflow-x-auto max-h-64 leading-relaxed">
                                  {JSON.stringify(ev.raw_payload && Object.keys(ev.raw_payload).length > 0 ? ev.raw_payload : ev, null, 2)}
                                </pre>
                              </div>
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
