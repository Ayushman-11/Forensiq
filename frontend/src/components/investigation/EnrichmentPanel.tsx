"use client";

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radar, AlertTriangle, Eye, CheckCircle, Clock } from 'lucide-react';

export default function EnrichmentPanel({ alert }: { alert: any }) {
  if (!alert) {
    return (
      <div className="h-full bg-[#141414] border border-[#2a2a2a] rounded-lg flex items-center justify-center text-[#383838]">
        <Radar className="w-8 h-8" />
      </div>
    );
  }

  const { enrichments = [], extracted_iocs = [] } = alert;

  if (extracted_iocs.length === 0) {
    return (
      <div className="h-full flex items-center justify-center flex-col gap-4 bg-[#141414] border border-[#2a2a2a] rounded-lg p-6">
        <div className="w-12 h-12 rounded bg-[#1c1c1c] border border-[#383838] flex items-center justify-center">
          <Radar className="w-5 h-5 text-[#555555]" />
        </div>
        <div className="text-center">
          <p className="font-bold text-[#888888] text-[11px] uppercase tracking-widest">No IOCs Detected</p>
        </div>
      </div>
    );
  }

  const maliciousCount = enrichments.filter((e: any) => e.reputation === 'malicious').length;
  const suspiciousCount = enrichments.filter((e: any) => e.reputation === 'suspicious').length;
  const notEnrichedYet = enrichments.length === 0;

  return (
    <div className="h-full flex flex-col bg-[#141414] border border-[#2a2a2a] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-[#2a2a2a] bg-[#1c1c1c] shrink-0">
        <div className="flex items-center gap-2 mb-3">
          <Radar className="w-4 h-4 text-[#FFAC41]" />
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-[#f0f0f0]">IOC Intelligence</h2>
        </div>

        {!notEnrichedYet ? (
          <div className="flex gap-2 flex-wrap">
            {maliciousCount > 0 && (
              <span className="bg-[#FF1E56]/10 text-[#FF1E56] border border-[#FF1E56]/30 px-2 py-1 rounded text-[9px] font-bold uppercase tracking-widest flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                {maliciousCount} Malicious
              </span>
            )}
            {suspiciousCount > 0 && (
              <span className="bg-[#FFAC41]/10 text-[#FFAC41] border border-[#FFAC41]/30 px-2 py-1 rounded text-[9px] font-bold uppercase tracking-widest flex items-center gap-1">
                <Eye className="w-3 h-3" />
                {suspiciousCount} Suspicious
              </span>
            )}
            {maliciousCount === 0 && suspiciousCount === 0 && (
              <span className="bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/30 px-2 py-1 rounded text-[9px] font-bold uppercase tracking-widest flex items-center gap-1">
                <CheckCircle className="w-3 h-3" />
                All Clean
              </span>
            )}
            <span className="bg-[#232323] border border-[#383838] text-[#888888] px-2 py-1 rounded text-[9px] font-bold uppercase tracking-widest">
              {enrichments.length} checked
            </span>
          </div>
        ) : (
          <p className="text-[10px] text-[#888888] font-bold uppercase tracking-widest flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" />
            {extracted_iocs.length} IOC{extracted_iocs.length !== 1 ? 's' : ''} pending
          </p>
        )}
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        {!notEnrichedYet ? (
          <div className="p-3 flex flex-col gap-2">
            <AnimatePresence>
              {enrichments.map((e: any, idx: number) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className="bg-[#1c1c1c] border border-[#2a2a2a] rounded p-3 hover:bg-[#232323] transition-colors"
                >
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <div className="font-mono text-[12px] text-[#f0f0f0] font-bold break-all">{e.ioc}</div>
                      <div className="text-[9px] text-[#555555] uppercase tracking-widest mt-1 font-bold">{e.ioc_type}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest border shrink-0 ml-2 ${
                      e.reputation === 'malicious' ? 'bg-[#FF1E56]/10 text-[#FF1E56] border-[#FF1E56]/30' :
                      e.reputation === 'suspicious' ? 'bg-[#FFAC41]/10 text-[#FFAC41] border-[#FFAC41]/30' :
                      e.reputation === 'benign' ? 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30' :
                      'bg-[#232323] text-[#888888] border-[#383838]'
                    }`}>
                      {e.reputation}
                    </span>
                  </div>
                  {/* Threat Score Bar */}
                  <div className="flex items-center gap-2 mt-3">
                    <div className="flex-1 bg-[#0e0e0e] border border-[#2a2a2a] rounded-none h-1.5 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.max(4, e.threat_score)}%` }}
                        transition={{ duration: 0.8, delay: idx * 0.05, type: "spring", stiffness: 100 }}
                        className={`h-1.5 ${
                          e.threat_score > 75 ? 'bg-[#FF1E56]' : 
                          e.threat_score > 25 ? 'bg-[#FFAC41]' : 
                          'bg-[#22c55e]'
                        }`}
                      />
                    </div>
                    <span className="font-mono text-[10px] font-bold text-[#888888]">{e.threat_score}/100</span>
                  </div>
                  <div className="mt-1 text-[9px] text-[#555555] font-bold uppercase tracking-widest">via {e.source}</div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        ) : (
          /* Pending IOC list */
          <div className="p-3 flex flex-col gap-1.5">
            <p className="text-[9px] font-bold text-[#555555] uppercase tracking-widest px-1 mb-1">Awaiting Analysis</p>
            {extracted_iocs.map((ioc: string, idx: number) => (
              <div key={idx} className="bg-[#1c1c1c] border border-[#2a2a2a] p-2.5 rounded flex justify-between items-center">
                <span className="font-mono text-[11px] truncate text-[#888888] font-bold">{ioc}</span>
                <Clock className="w-3.5 h-3.5 text-[#555555] shrink-0 ml-2" />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
