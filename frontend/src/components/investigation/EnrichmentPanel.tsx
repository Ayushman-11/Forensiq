"use client";

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radar, AlertTriangle, Eye, CheckCircle, Clock, ShieldAlert } from 'lucide-react';
import type { AlertRecord, Enrichment } from '@/lib/types';

export default function EnrichmentPanel({ alert }: { alert: AlertRecord }) {
  if (!alert) {
    return (
      <div className="h-full bg-[#0C1322] border border-[#1E2E48] rounded-xl flex items-center justify-center text-slate-500">
        <Radar className="w-8 h-8" />
      </div>
    );
  }

  const { enrichments = [], extracted_iocs = [] } = alert;

  if (extracted_iocs.length === 0) {
    return (
      <div className="h-full flex items-center justify-center flex-col gap-3 bg-[#0C1322] border border-[#1E2E48] rounded-xl p-8 text-center">
        <div className="w-12 h-12 rounded-xl bg-[#121B2C] border border-[#23354E] flex items-center justify-center text-slate-400">
          <Radar className="w-5 h-5 text-slate-400" />
        </div>
        <div>
          <p className="font-bold text-slate-300 text-xs uppercase tracking-wider">No IOCs Extracted</p>
          <p className="text-[11px] text-slate-400 mt-0.5">No IP addresses, domains, or hashes found in payload</p>
        </div>
      </div>
    );
  }

  const maliciousCount = enrichments.filter((e: Enrichment) => e.reputation === 'malicious').length;
  const suspiciousCount = enrichments.filter((e: Enrichment) => e.reputation === 'suspicious').length;
  const notEnrichedYet = enrichments.length === 0;

  return (
    <div className="h-full flex flex-col bg-[#0C1322] border border-[#1E2E48] rounded-xl overflow-hidden shadow-lg">
      {/* Header */}
      <div className="p-4 border-b border-[#1A2942] bg-[#0E1726] shrink-0">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">IOC Threat Intelligence</h2>
          </div>
          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-[#16233B] text-slate-300 border border-[#223659]">
            VirusTotal / AlienVault
          </span>
        </div>

        {!notEnrichedYet ? (
          <div className="flex gap-2 flex-wrap">
            {maliciousCount > 0 && (
              <span className="bg-rose-500/15 text-rose-300 border border-rose-500/40 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-[0_0_10px_rgba(244,63,94,0.2)]">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                {maliciousCount} Malicious
              </span>
            )}
            {suspiciousCount > 0 && (
              <span className="bg-orange-500/15 text-orange-300 border border-orange-500/40 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5">
                <Eye className="w-3.5 h-3.5 text-orange-400" />
                {suspiciousCount} Suspicious
              </span>
            )}
            {maliciousCount === 0 && suspiciousCount === 0 && (
              <span className="bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                All Clean
              </span>
            )}
            <span className="bg-[#121B2C] border border-[#22344D] text-slate-300 px-2.5 py-1 rounded-md text-[10px] font-mono font-bold uppercase tracking-wider">
              {enrichments.length} checked
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs text-amber-300 font-semibold bg-amber-500/10 border border-amber-500/30 px-3 py-1.5 rounded-lg">
            <Clock className="w-3.5 h-3.5" />
            <span>{extracted_iocs.length} IOC{extracted_iocs.length !== 1 ? 's' : ''} awaiting threat enrichment</span>
          </div>
        )}
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        {!notEnrichedYet ? (
          <div className="p-3.5 flex flex-col gap-2.5">
            <AnimatePresence>
              {enrichments.map((e: Enrichment, idx: number) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className="bg-[#10192A] border border-[#1C2C44] rounded-lg p-3.5 hover:bg-[#142034] hover:border-cyan-500/40 transition-all shadow-sm"
                >
                  <div className="flex justify-between items-start gap-2 mb-2">
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-xs text-white font-bold break-all">{e.ioc}</div>
                      <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-1 font-semibold">{e.ioc_type}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border shrink-0 ${
                      e.reputation === 'malicious' ? 'bg-rose-500/15 text-rose-300 border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.3)]' :
                      e.reputation === 'suspicious' ? 'bg-orange-500/15 text-orange-300 border-orange-500/40' :
                      e.reputation === 'benign' ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40' :
                      'bg-[#16233B] text-slate-300 border-[#223554]'
                    }`}>
                      {e.reputation}
                    </span>
                  </div>

                  {/* Threat Score Bar */}
                  <div className="flex items-center gap-3 mt-3">
                    <div className="flex-1 bg-[#070B12] border border-[#1C2C44] rounded-full h-2 overflow-hidden p-0.5">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.max(4, e.threat_score ?? 0)}%` }}
                        transition={{ duration: 0.8, delay: idx * 0.05 }}
                        className={`h-full rounded-full ${
                          (e.threat_score ?? 0) > 75 ? 'bg-gradient-to-r from-orange-500 to-rose-500 shadow-[0_0_8px_#f43f5e]' :
                          (e.threat_score ?? 0) > 25 ? 'bg-gradient-to-r from-amber-400 to-orange-500' :
                          'bg-emerald-400'
                        }`}
                      />
                    </div>
                    <span className="font-mono text-xs font-bold text-white shrink-0">
                      {e.threat_score ?? 0}<span className="text-slate-400 text-[10px]">/100</span>
                    </span>
                  </div>

                  <div className="mt-1.5 text-[10px] text-slate-400 font-mono flex items-center justify-between">
                    <span>Source: {e.source || "Threat Intel Feed"}</span>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        ) : (
          /* Pending IOC list */
          <div className="p-3.5 flex flex-col gap-2">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider px-1">Extracted Indicators</p>
            {extracted_iocs.map((ioc: string, idx: number) => (
              <div key={idx} className="bg-[#10192A] border border-[#1C2C44] p-3 rounded-lg flex justify-between items-center">
                <span className="font-mono text-xs truncate text-cyan-300 font-semibold">{ioc}</span>
                <Clock className="w-3.5 h-3.5 text-amber-400 shrink-0 ml-2" />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
