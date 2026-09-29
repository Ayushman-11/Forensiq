"use client";

import { useState, useEffect } from 'react';
import ContextPanel from '@/components/investigation/ContextPanel';
import EnrichmentPanel from '@/components/investigation/EnrichmentPanel';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, RefreshCw, Filter, Monitor, ChevronDown, ChevronRight, Loader2, Target } from 'lucide-react';
import { apiFetch } from '@/lib/api';

export default function AlertsPage() {
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const params = new URLSearchParams();
      params.append('limit', '100');
      if (severityFilter !== 'All') params.append('severity', severityFilter);
      if (statusFilter !== 'All') params.append('status', statusFilter);
      if (search) params.append('search', search);

      const res = await apiFetch(`/api/v1/alerts?${params.toString()}`);
      if (res.ok) {
        setAlerts(await res.json());
      }
    } catch (e) {
      console.error('Failed to fetch alerts', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, [severityFilter, statusFilter, search]);

  const formatTime = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      return date.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="flex flex-col gap-4 max-w-[1400px] mx-auto pb-10">
      {/* Header & Filter Bar */}
      <div className="flex justify-between items-center bg-[#141414] border border-[#2a2a2a] rounded-lg p-3 shrink-0 sticky top-[56px] z-30 shadow-md">
        <div className="flex gap-4 items-center flex-1">
          <div className="relative w-96">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[#555555] w-4 h-4" />
            <input 
              type="text" 
              placeholder="Search by Title or Host..." 
              className="w-full bg-[#0e0e0e] border border-[#2a2a2a] rounded py-2 pl-10 pr-4 text-xs focus:border-[#383838] focus:bg-[#1c1c1c] outline-none text-[#f0f0f0] transition-all font-mono placeholder:text-[#555555]"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <div className="relative">
              <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#555555] w-3 h-3" />
              <select 
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#0e0e0e] border border-[#2a2a2a] rounded py-2 pl-8 pr-8 text-[11px] uppercase tracking-wider font-bold outline-none text-[#f0f0f0] cursor-pointer hover:bg-[#1c1c1c] transition-all appearance-none"
              >
                <option value="All">All Severity</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            <div className="relative">
              <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#555555] w-3 h-3" />
              <select 
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-[#0e0e0e] border border-[#2a2a2a] rounded py-2 pl-8 pr-8 text-[11px] uppercase tracking-wider font-bold outline-none text-[#f0f0f0] cursor-pointer hover:bg-[#1c1c1c] transition-all appearance-none"
              >
                <option value="All">All Status</option>
                <option value="Investigated">Investigated</option>
                <option value="Investigating">Investigating</option>
                <option value="New">New</option>
              </select>
            </div>
          </div>
        </div>
        <div className="flex gap-2 items-center">
          <span className="text-[10px] text-[#888888] font-bold uppercase tracking-widest mr-2">
            {alerts.length} Total
          </span>
          <button 
            onClick={() => fetchAlerts()} 
            className="text-[#888888] hover:text-white transition-all flex items-center justify-center p-2 rounded bg-[#0e0e0e] border border-[#2a2a2a] hover:border-[#383838] cursor-pointer"
            title="Refresh Data"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Single Column Alert List */}
      <div className="flex flex-col gap-3 relative">
        {loading ? (
          <div className="p-12 text-center text-[#555555] font-bold text-xs uppercase tracking-widest flex flex-col items-center gap-4">
            <Loader2 className="w-8 h-8 animate-spin" />
            Synchronizing Queue...
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center text-[#555555] border border-[#2a2a2a] border-dashed rounded-lg font-bold text-xs uppercase tracking-widest">
            No matching events found in queue.
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {alerts.map((alert) => {
              const isCrit = alert.severity === 'critical';
              const isHigh = alert.severity === 'high';
              const isMed = alert.severity === 'medium';
              const sevColor = isCrit ? '#FF1E56' : isHigh ? '#FFAC41' : isMed ? '#3b82f6' : '#525252';
              const isExpanded = expandedAlertId === alert._id;
              
              const isInvestigating = alert.status === "Investigating";
              const isInvestigated = alert.status === "Investigated" || alert.status === "Investigation Failed";

              return (
                <motion.div 
                  layout
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  key={alert._id} 
                  className={`border rounded-lg overflow-hidden transition-all duration-300 ${
                    isExpanded 
                      ? 'bg-[#141414] border-[#383838] shadow-[0_0_15px_rgba(0,0,0,0.5)]' 
                      : 'bg-[#0e0e0e] border-[#2a2a2a] hover:border-[#383838] hover:bg-[#141414]'
                  }`}
                >
                  {/* Accordion Header */}
                  <div 
                    onClick={() => setExpandedAlertId(isExpanded ? null : alert._id)}
                    className="p-4 cursor-pointer flex items-center justify-between"
                  >
                    <div className="flex items-center gap-4 flex-1">
                      <div className="w-5 h-5 flex items-center justify-center text-[#555555]">
                        {isExpanded ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
                      </div>
                      
                      <div className="flex items-center gap-2 w-28 shrink-0">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: sevColor }}></span>
                        <span className="text-[11px] font-bold uppercase tracking-widest" style={{ color: sevColor }}>
                          {alert.severity}
                        </span>
                      </div>

                      <div className="flex-1 flex flex-col gap-1">
                        <span className="text-[15px] font-bold leading-none text-[#f0f0f0] truncate max-w-xl">
                          {alert.title}
                        </span>
                        <div className="flex items-center gap-4 text-[10px] text-[#888888] font-mono font-bold uppercase tracking-widest">
                          <span className="flex items-center gap-1.5"><Monitor className="w-3 h-3 text-[#3b82f6]" /> {alert.host || '-'}</span>
                          <span>|</span>
                          <span className="flex items-center gap-1.5"><Target className="w-3 h-3 text-[#FFAC41]" /> {alert.rule_name || 'Generic'}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-6 shrink-0">
                      {isInvestigating && (
                        <div className="flex items-center gap-2 text-[#FFAC41] bg-[#FFAC41]/10 border border-[#FFAC41]/30 px-3 py-1 rounded text-[10px] font-bold uppercase tracking-widest">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          AI Investigating...
                        </div>
                      )}
                      
                      {isInvestigated && (
                        <div className="flex flex-col items-end gap-1">
                          <span className="text-[10px] text-[#555555] font-bold uppercase tracking-widest">Confidence</span>
                          <span className={`px-2 py-0.5 rounded text-[11px] border font-bold ${
                            alert.ai_confidence > 80 ? 'border-[#FF1E56]/30 text-[#FF1E56] bg-[#FF1E56]/10' : 
                            alert.ai_confidence > 50 ? 'border-[#FFAC41]/30 text-[#FFAC41] bg-[#FFAC41]/10' : 
                            'border-[#383838] text-[#888888] bg-[#232323]'
                          }`}>
                            {alert.ai_confidence}%
                          </span>
                        </div>
                      )}

                      <div className="flex flex-col items-end gap-1 w-32">
                        <span className="text-[10px] text-[#555555] font-bold uppercase tracking-widest">Detected At</span>
                        <span className="text-[11px] text-[#888888] font-bold font-mono tracking-wider">{formatTime(alert.created_at)}</span>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Content Area */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="border-t border-[#2a2a2a] bg-[#141414] overflow-hidden"
                      >
                        {isInvestigating ? (
                          <div className="p-12 flex flex-col items-center justify-center gap-4">
                            <Loader2 className="w-8 h-8 animate-spin text-[#FFAC41]" />
                            <div className="text-center">
                              <p className="text-[13px] font-bold text-[#f0f0f0] mb-1">AI Agents Active</p>
                              <p className="text-[11px] text-[#888888] uppercase tracking-widest font-bold">Extracting IOCs & Threat Intel Correlation...</p>
                            </div>
                          </div>
                        ) : isInvestigated ? (
                          <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                            {/* We re-use the Context/Enrichment panels but without borders if possible, or they can stay as cards */}
                            <div className="col-span-1 border-r border-[#2a2a2a] pr-4">
                               <ContextPanel alert={alert} />
                            </div>
                            <div className="col-span-1 pl-2">
                               <EnrichmentPanel alert={alert} />
                            </div>
                          </div>
                        ) : (
                          <div className="p-8 text-center">
                            <p className="text-[11px] text-[#888888] uppercase tracking-widest font-bold">Alert queued. Awaiting processing...</p>
                          </div>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
