"use client";

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, Monitor, ChevronDown, CheckCircle, Search, Cpu, Target, Braces } from 'lucide-react';

export default function ContextPanel({ alert }: { alert: any }) {
  const [showRaw, setShowRaw] = useState(false);

  if (!alert) {
    return (
      <div className="h-full flex items-center justify-center flex-col gap-4 bg-[#141414] border border-[#2a2a2a] rounded-lg">
        <div className="w-12 h-12 rounded border border-[#383838] bg-[#1c1c1c] flex items-center justify-center">
          <Search className="w-5 h-5 text-[#555555]" />
        </div>
        <p className="font-bold text-[11px] text-[#555555] uppercase tracking-widest">Select an alert for context</p>
      </div>
    );
  }

  const { context = {} } = alert;

  return (
    <div className="h-full flex flex-col bg-[#141414] border border-[#2a2a2a] rounded-lg overflow-hidden">
      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
        
        {/* Core Attributes */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-[#1c1c1c] p-3 rounded border border-[#2a2a2a]">
            <div className="flex items-center gap-1.5 mb-1.5">
              <Monitor className="w-3.5 h-3.5 text-[#3b82f6]" />
              <div className="text-[9px] font-bold text-[#888888] uppercase tracking-widest">Target Host</div>
            </div>
            <div className="font-mono text-sm text-[#f0f0f0] truncate">{alert.host || '-'}</div>
          </div>
          <div className="bg-[#1c1c1c] p-3 rounded border border-[#2a2a2a]">
            <div className="flex items-center gap-1.5 mb-1.5">
              <User className="w-3.5 h-3.5 text-[#FFAC41]" />
              <div className="text-[9px] font-bold text-[#888888] uppercase tracking-widest">Target User</div>
            </div>
            <div className="font-mono text-sm text-[#f0f0f0] truncate">{alert.user || '-'}</div>
          </div>
        </div>

        {/* Dynamic Context Fields */}
        {Object.keys(context).length > 0 && (
          <div className="flex flex-col gap-2.5">
            <h3 className="text-[10px] font-bold text-[#888888] uppercase tracking-widest flex items-center gap-1.5 border-b border-[#2a2a2a] pb-1">
              <Braces className="w-3 h-3 text-[#FF1E56]" />
              Extracted Context
            </h3>
            <div className="grid grid-cols-1 gap-2">
              {Object.entries(context).map(([key, value]) => (
                <div key={key} className="bg-[#1c1c1c] border border-[#2a2a2a] rounded p-2.5 flex flex-col gap-1">
                  <div className="text-[9px] text-[#FFAC41] font-bold uppercase tracking-widest">
                    {key.replace(/_/g, ' ')}
                  </div>
                  <div className="font-mono text-[12px] text-[#f0f0f0] break-words whitespace-pre-wrap leading-tight">
                    {String(value)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* MITRE Tags */}
        {alert.mitre_tactic && (
          <div className="flex flex-col gap-2.5">
            <h3 className="text-[10px] font-bold text-[#888888] uppercase tracking-widest flex items-center gap-1.5 border-b border-[#2a2a2a] pb-1">
              <Target className="w-3 h-3 text-[#3b82f6]" />
              MITRE ATT&CK
            </h3>
            <div className="flex gap-2 flex-wrap">
              <span className="bg-[#1c1c1c] border border-[#383838] text-[#f0f0f0] px-2 py-1 rounded text-[10px] font-mono font-bold uppercase tracking-wide">
                {alert.mitre_tactic}
              </span>
              <span className="bg-[#1c1c1c] border border-[#383838] text-[#f0f0f0] px-2 py-1 rounded text-[10px] font-mono font-bold uppercase tracking-wide">
                {alert.mitre_technique}
              </span>
            </div>
          </div>
        )}

        {/* Raw Data Toggle */}
        <div className="mt-2 pt-4 border-t border-[#2a2a2a]">
          <button 
            onClick={() => setShowRaw(!showRaw)}
            className="flex items-center gap-1.5 text-[#888888] hover:text-[#f0f0f0] font-bold text-[10px] uppercase tracking-widest transition-colors cursor-pointer"
          >
            <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-300 ${showRaw ? 'rotate-180' : ''}`} />
            {showRaw ? 'Hide Raw Splunk Data' : 'View Raw Splunk Data'}
          </button>
          
          <AnimatePresence>
            {showRaw && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <pre className="mt-3 bg-[#0e0e0e] p-3 rounded border border-[#2a2a2a] overflow-x-auto text-[10px] font-mono text-[#3b82f6] max-h-[300px] overflow-y-auto leading-relaxed">
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
