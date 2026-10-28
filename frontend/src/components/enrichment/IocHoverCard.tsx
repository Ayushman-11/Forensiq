"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Copy, Check, ExternalLink, ShieldAlert, ShieldCheck, AlertTriangle, Search, Globe, Hash } from "lucide-react";
import Link from "next/link";
import { defangIoc, detectIocType, type IocType } from "@/lib/defang";
import type { Enrichment } from "@/lib/types";

interface IocHoverCardProps {
  ioc: string;
  type?: string;
  enrichment?: Enrichment;
  className?: string;
  showBadge?: boolean;
}

export default function IocHoverCard({
  ioc,
  type,
  enrichment,
  className = "",
  showBadge = true,
}: IocHoverCardProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedDefanged, setCopiedDefanged] = useState(false);

  const detectedType: IocType = (type?.toLowerCase() as IocType) || detectIocType(ioc);
  const defanged = defangIoc(ioc);

  const handleCopyRaw = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ioc);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleCopyDefanged = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(defanged);
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const reputation = enrichment?.reputation?.toLowerCase() || "unknown";
  const isMalicious = reputation === "malicious";
  const isSuspicious = reputation === "suspicious";
  const isClean = reputation === "clean" || reputation === "benign";

  // External URLs
  const vtUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`;
  const abuseUrl = detectedType === "ip" 
    ? `https://www.abuseipdb.com/check/${encodeURIComponent(ioc)}` 
    : null;

  return (
    <div
      className="relative inline-block"
      onMouseEnter={() => setIsOpen(true)}
      onMouseLeave={() => setIsOpen(false)}
    >
      <span
        className={`font-mono text-xs cursor-pointer inline-flex items-center gap-1.5 transition-colors ${
          isMalicious
            ? "text-rose-400 hover:text-rose-300 font-semibold"
            : isSuspicious
            ? "text-amber-400 hover:text-amber-300 font-semibold"
            : isClean
            ? "text-emerald-400 hover:text-emerald-300"
            : "text-cyan-300 hover:text-cyan-200"
        } ${className}`}
      >
        <span className="underline decoration-dotted underline-offset-4">{ioc}</span>
        {showBadge && (
          <span
            className={`text-[9px] px-1.5 py-0.2 rounded font-sans uppercase tracking-wider border ${
              isMalicious
                ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                : isSuspicious
                ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                : isClean
                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                : "bg-slate-800 text-slate-300 border-slate-700"
            }`}
          >
            {isMalicious ? "Malicious" : isSuspicious ? "Suspicious" : isClean ? "Clean" : detectedType}
          </span>
        )}
      </span>

      {/* Floating Rich Popover Card */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            transition={{ duration: 0.15 }}
            className="absolute z-50 bottom-full left-0 mb-2 w-80 rounded-xl bg-[var(--card-bg)] border border-[var(--border-color)] p-3.5 shadow-2xl text-left pointer-events-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Popover Header */}
            <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-2.5 mb-2.5">
              <div className="flex items-center gap-2">
                {detectedType === "ip" ? (
                  <Globe className="w-4 h-4 text-[var(--text-secondary)]" />
                ) : detectedType === "hash" ? (
                  <Hash className="w-4 h-4 text-[var(--text-secondary)]" />
                ) : (
                  <Search className="w-4 h-4 text-[var(--text-secondary)]" />
                )}
                <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-primary)]">
                  IOC Intelligence
                </span>
              </div>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                {detectedType}
              </span>
            </div>

            {/* Defanged & Raw Value Box */}
            <div className="bg-[var(--surface-secondary)] rounded-lg p-2.5 border border-[var(--border-subtle)] mb-3 space-y-1.5">
              <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)]">
                <span className="uppercase font-semibold">Defanged Representation:</span>
                <button
                  onClick={handleCopyDefanged}
                  className="flex items-center gap-1 text-[var(--text-primary)] hover:underline transition-colors cursor-pointer"
                >
                  {copiedDefanged ? (
                    <>
                      <Check className="w-3 h-3 text-[#22C55E]" />
                      <span className="text-[#22C55E] font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-[var(--text-muted)]" />
                      <span>Copy Defanged</span>
                    </>
                  )}
                </button>
              </div>
              <div className="font-mono text-xs text-[var(--text-primary)] break-all select-all font-semibold bg-[var(--surface-elevated)] p-1.5 rounded border border-[var(--border-color)]">
                {defanged}
              </div>
            </div>

            {/* Threat Assessment / Reputation Score */}
            <div className="mb-3 space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[var(--text-muted)] font-medium">Reputation Status:</span>
                <span
                  className={`font-bold uppercase tracking-wider flex items-center gap-1 ${
                    isMalicious
                      ? "text-[#EF4444]"
                      : isSuspicious
                      ? "text-[#F59E0B]"
                      : isClean
                      ? "text-[#22C55E]"
                      : "text-[var(--text-muted)]"
                  }`}
                >
                  {isMalicious && <ShieldAlert className="w-3.5 h-3.5" />}
                  {isSuspicious && <AlertTriangle className="w-3.5 h-3.5" />}
                  {isClean && <ShieldCheck className="w-3.5 h-3.5" />}
                  {reputation.toUpperCase()}
                </span>
              </div>

              {enrichment?.threat_score !== undefined && (
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] text-[var(--text-muted)] font-mono">
                    <span>Threat Confidence:</span>
                    <span className="text-[var(--text-primary)] font-bold">{enrichment.threat_score}/100</span>
                  </div>
                  <div className="h-1.5 w-full bg-[var(--surface-elevated)] rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        enrichment.threat_score > 70
                          ? "bg-[#EF4444]"
                          : enrichment.threat_score > 30
                          ? "bg-[#F59E0B]"
                          : "bg-[#22C55E]"
                      }`}
                      style={{ width: `${Math.min(100, Math.max(5, enrichment.threat_score))}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Pivot and External Action Bar */}
            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[var(--border-color)]">
              <Link
                href={`/search?q=${encodeURIComponent(`search "${ioc}"`)}`}
                className="flex items-center justify-center gap-1.5 py-1.5 px-2 rounded-md bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] text-[10px] font-semibold text-[var(--text-primary)] transition-colors border border-[var(--border-color)]"
              >
                <Search className="w-3 h-3 text-[var(--text-muted)]" />
                <span>Pivot to SPL</span>
              </Link>
              <a
                href={vtUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center justify-center gap-1.5 py-1.5 px-2 rounded-md bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] text-[10px] font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors border border-[var(--border-color)]"
              >
                <ExternalLink className="w-3 h-3 text-[var(--text-muted)]" />
                <span>VirusTotal</span>
              </a>
            </div>
            {abuseUrl && (
              <div className="mt-1.5">
                <a
                  href={abuseUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="w-full flex items-center justify-center gap-1.5 py-1 px-2 rounded-md bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] text-[9px] font-mono text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors border border-[var(--border-subtle)]"
                >
                  <ExternalLink className="w-2.5 h-2.5" />
                  <span>Verify on AbuseIPDB</span>
                </a>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
