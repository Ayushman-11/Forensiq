"use client";

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, Monitor, ChevronDown, Search, Target, Braces, Terminal } from 'lucide-react';
import type { AlertRecord } from '@/lib/types';

export default function ContextPanel({ alert }: { alert: AlertRecord }) {
  const [showRaw, setShowRaw] = useState(false);

  if (!alert) {
    return (
      <div className="h-full flex items-center justify-center flex-col gap-3 bg-[#0C1322] border border-[#1E2E48] rounded-xl p-8">
        <div className="w-12 h-12 rounded-xl border border-[#23354E] bg-[#121B2C] flex items-center justify-center text-slate-400">
          <Search className="w-5 h-5" />
        </div>
        <p className="font-bold text-xs text-slate-400 uppercase tracking-widest">Select an alert for context</p>
      </div>
    );
  }

  const { context = {} } = alert;

  return (
    <div className="h-full flex flex-col bg-[#0C1322] border border-[#1E2E48] rounded-xl overflow-hidden shadow-lg">
      {/* Header */}
      <div className="p-4 border-b border-[#1A2942] bg-[#0E1726] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Braces className="w-4 h-4 text-cyan-400" />
          <h2 className="text-xs font-bold uppercase tracking-wider text-white">Extracted Telemetry Context</h2>
        </div>
        <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-[#16233B] text-cyan-300 border border-[#223659]">
          Sysmon / AuditD
        </span>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
        
        {/* Core Attributes */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-[#10192A] p-3.5 rounded-lg border border-[#1C2C44]">
            <div className="flex items-center gap-1.5 mb-1.5">
              <Monitor className="w-3.5 h-3.5 text-cyan-400" />
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Target Host</div>
            </div>
            <div className="font-mono text-sm font-semibold text-white truncate">{alert.host || 'Unknown'}</div>
          </div>
          <div className="bg-[#10192A] p-3.5 rounded-lg border border-[#1C2C44]">
            <div className="flex items-center gap-1.5 mb-1.5">
              <User className="w-3.5 h-3.5 text-amber-400" />
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Target User</div>
            </div>
            <div className="font-mono text-sm font-semibold text-white truncate">{alert.user || 'Unknown'}</div>
          </div>
        </div>

        {/* Dynamic Context Fields */}
        {Object.keys(context).length > 0 && (
          <div className="flex flex-col gap-2.5">
            <h3 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 border-b border-[#1A2942] pb-1.5">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              Execution Indicators
            </h3>
            <div className="grid grid-cols-1 gap-2.5">
              {Object.entries(context).map(([key, value]) => (
                <div key={key} className="bg-[#10192A] border border-[#1C2C44] rounded-lg p-3 flex flex-col gap-1.5">
                  <div className="text-[10px] text-amber-400 font-bold uppercase tracking-wider">
                    {key.replace(/_/g, ' ')}
                  </div>
                  <div className="font-mono text-xs text-slate-100 break-words whitespace-pre-wrap leading-relaxed bg-[#0A101C] p-2 rounded border border-[#16243A]">
                    {String(value)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* MITRE ATT&CK Mapping */}
        {alert.mitre_tactic && (
          <div className="flex flex-col gap-2.5">
            <h3 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 border-b border-[#1A2942] pb-1.5">
              <Target className="w-3.5 h-3.5 text-rose-400" />
              MITRE ATT&CK Mapping
            </h3>
            <div className="flex gap-2 flex-wrap">
              <span className="bg-[#16233B] border border-cyan-500/40 text-cyan-300 px-2.5 py-1 rounded-md text-xs font-mono font-bold tracking-wide">
                Tactic: {alert.mitre_tactic}
              </span>
              <span className="bg-[#16233B] border border-rose-500/40 text-rose-300 px-2.5 py-1 rounded-md text-xs font-mono font-bold tracking-wide">
                Technique: {alert.mitre_technique}
              </span>
            </div>
          </div>
        )}

        {/* Raw Data Toggle */}
        <div className="mt-2 pt-4 border-t border-[#1A2942]">
          <button 
            onClick={() => setShowRaw(!showRaw)}
            className="flex items-center gap-2 text-slate-300 hover:text-white font-bold text-xs uppercase tracking-wider transition-colors cursor-pointer"
          >
            <ChevronDown className={`w-4 h-4 transition-transform duration-300 text-cyan-400 ${showRaw ? 'rotate-180' : ''}`} />
            {showRaw ? 'Hide Raw Splunk Event' : 'View Raw Splunk Event Payload'}
          </button>
          
          <AnimatePresence>
            {showRaw && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <pre className="mt-3 bg-[#070B12] p-3.5 rounded-lg border border-[#1A2942] overflow-x-auto text-[11px] font-mono text-cyan-300 max-h-[300px] overflow-y-auto leading-relaxed shadow-inner">
                  {JSON.stringify(alert.raw_event || alert.raw_alert_data, null, 2)}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

      </div>
    </div>
  );
}
