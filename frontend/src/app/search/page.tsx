"use client";

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Search, Loader2, AlertCircle, Clock, Monitor, Code, Hash } from 'lucide-react';
import { apiFetch } from '@/lib/api';

const QUICK_QUERIES = [
  { label: 'Failed Logins', query: 'search index=windows source="XmlWinEventLog:Security" EventCode=4625' },
  { label: 'PowerShell', query: 'search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell*"' },
  { label: 'Network Conns', query: 'search index=windows EventCode=3' },
  { label: 'DNS Queries', query: 'search index=windows EventCode=22' },
];

export default function SearchPage() {
  const [query, setQuery] = useState('search index=windows EventCode=4625');
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTime, setSearchTime] = useState<number | null>(null);

  const handleSearch = async (q?: string) => {
    const searchQuery = q ?? query;
    if (!searchQuery.trim()) return;
    if (q) setQuery(q);

    setLoading(true);
    setError(null);
    setEvents([]);
    const start = Date.now();

    try {
      const res = await apiFetch('/api/v1/search/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: searchQuery,
          earliest_time: '-24h',
          latest_time: 'now',
          limit: 100
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setEvents(data.events || []);
      setSearchTime(Date.now() - start);
    } catch (err: any) {
      setError(err.message || 'An error occurred while searching logs');
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleString();
    } catch { return dateStr; }
  };

  return (
    <div className="flex flex-col gap-4 h-[calc(100vh-120px)] pb-2 max-w-[1800px] mx-auto">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Terminal className="w-6 h-6 text-[#FF1E56]" />
            Raw Log Search
          </h2>
          <p className="text-[11px] font-bold text-[#888888] uppercase tracking-widest mt-1.5">Query SIEM via SPL</p>
        </div>
      </div>

      {/* Quick Filters */}
      <div className="flex gap-2 flex-wrap shrink-0">
        {QUICK_QUERIES.map((q) => (
          <button
            key={q.label}
            onClick={() => handleSearch(q.query)}
            className="bg-[#1c1c1c] border border-[#2a2a2a] px-3 py-1.5 rounded text-[10px] font-bold uppercase tracking-widest text-[#888888] hover:text-[#f0f0f0] hover:border-[#383838] transition-all cursor-pointer"
          >
            {q.label}
          </button>
        ))}
      </div>

      {/* Search Input Bar */}
      <div className="bg-[#141414] border border-[#2a2a2a] rounded-lg p-2.5 flex gap-2 shrink-0">
        <div className="flex-1 bg-[#0e0e0e] border border-[#2a2a2a] rounded px-3 py-2 flex items-center gap-2 focus-within:border-[#383838] transition-all">
          <Terminal className="w-4 h-4 text-[#555555] shrink-0" />
          <input
            type="text"
            placeholder='search index=windows EventCode=4625 | stats count by IpAddress'
            className="w-full bg-transparent border-none outline-none text-sm font-mono text-[#3b82f6] placeholder:text-[#383838] font-bold"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          />
        </div>
        <button
          onClick={() => handleSearch()}
          disabled={loading}
          className="bg-[#22c55e] text-black hover:bg-[#22c55e]/90 disabled:opacity-50 disabled:bg-[#1c1c1c] disabled:text-[#555555] transition-all px-6 rounded flex items-center gap-2 font-bold text-[11px] uppercase tracking-widest cursor-pointer"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {loading ? 'Searching' : 'Search'}
        </button>
      </div>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="bg-[#FF1E56]/10 text-[#FF1E56] px-4 py-3 rounded border border-[#FF1E56]/30 font-bold text-xs flex items-center gap-3 shrink-0"
          >
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results Table */}
      <div className="flex-1 bg-[#141414] border border-[#2a2a2a] rounded-lg overflow-hidden flex flex-col min-h-0">
        <div className="p-3 border-b border-[#2a2a2a] bg-[#1c1c1c] flex justify-between items-center shrink-0">
          <div className="flex items-center gap-3">
            <h3 className="font-bold text-[11px] uppercase tracking-widest text-[#888888]">
              Results {events.length > 0 && <span className="text-[#f0f0f0] ml-1">({events.length})</span>}
            </h3>
            {searchTime !== null && events.length > 0 && (
              <span className="text-[10px] text-[#555555] font-bold uppercase tracking-widest flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {(searchTime / 1000).toFixed(2)}s
              </span>
            )}
          </div>
        </div>

        <div className="overflow-auto flex-1">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-[#555555]">
              <div className="w-6 h-6 border-2 border-[#555555] border-t-transparent rounded-full animate-spin" />
              <p className="font-bold text-[11px] uppercase tracking-widest">Executing Query</p>
            </div>
          ) : events.length === 0 && !error ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-[#383838]">
              <Code className="w-8 h-8" />
              <p className="font-bold text-[11px] uppercase tracking-widest">Awaiting SPL Query</p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse whitespace-nowrap">
              <thead className="sticky top-0 bg-[#0e0e0e] border-b border-[#2a2a2a] z-10">
                <tr>
                  <th className="py-2.5 px-4 text-[10px] font-bold text-[#555555] uppercase tracking-widest w-40">
                    <span className="flex items-center gap-1.5"><Clock className="w-3 h-3" />Time</span>
                  </th>
                  <th className="py-2.5 px-4 text-[10px] font-bold text-[#555555] uppercase tracking-widest w-40">
                    <span className="flex items-center gap-1.5"><Monitor className="w-3 h-3" />Host</span>
                  </th>
                  <th className="py-2.5 px-4 text-[10px] font-bold text-[#555555] uppercase tracking-widest w-32">Source</th>
                  <th className="py-2.5 px-4 text-[10px] font-bold text-[#555555] uppercase tracking-widest w-24">
                    <span className="flex items-center gap-1.5"><Hash className="w-3 h-3" />Event ID</span>
                  </th>
                  <th className="py-2.5 px-4 text-[10px] font-bold text-[#555555] uppercase tracking-widest w-full">Raw Data</th>
                </tr>
              </thead>
              <tbody className="font-mono text-sm">
                {events.map((ev, i) => (
                  <tr
                    key={i}
                    className="border-b border-[#2a2a2a] hover:bg-[#1c1c1c] transition-colors"
                  >
                    <td className="py-2 px-4 text-xs text-[#888888]">{formatTime(ev.timestamp)}</td>
                    <td className="py-2 px-4 text-xs font-bold text-[#f0f0f0]">{ev.hostname || '-'}</td>
                    <td className="py-2 px-4 text-[10px] uppercase text-[#3b82f6] font-bold">{ev.provider || '-'}</td>
                    <td className="py-2 px-4">
                      <span className="text-[10px] bg-[#232323] border border-[#383838] px-1.5 py-0.5 rounded font-bold text-[#f0f0f0]">{ev.event_id || '-'}</span>
                    </td>
                    <td className="py-2 px-4 text-[11px] text-[#555555] truncate max-w-xl">
                      {ev.command_line || ev.process_name || JSON.stringify(ev.raw_payload)?.slice(0, 160)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
