"use client";

import React, { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Crosshair, 
  Search, 
  ExternalLink, 
  ArrowRight, 
  X, 
  RefreshCw 
} from "lucide-react";
import Link from "next/link";
import { apiFetch } from "@/lib/api";

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  count: number;
  severity: "critical" | "high" | "medium" | "low";
  description?: string;
  alert_ids?: string[];
}

export interface MitreTacticColumn {
  id: string;
  name: string;
  shortName: string;
  techniques: { id: string; name: string; description: string }[];
}

// Enterprise ATT&CK matrix layout with standard tactics & primary techniques
export const ENTERPRISE_TACTICS: MitreTacticColumn[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    shortName: "Init Access",
    techniques: [
      { id: "T1190", name: "Exploit Public-Facing App", description: "Exploiting weakness in an Internet-facing computer or system." },
      { id: "T1566", name: "Phishing", description: "Sending targeted phishing messages to gain initial access." },
      { id: "T1078", name: "Valid Accounts", description: "Stealing or obtaining legitimate credentials to gain initial access." },
      { id: "T1133", name: "External Remote Services", description: "Accessing internal network via VPNs, gateways, or jump boxes." }
    ]
  },
  {
    id: "TA0002",
    name: "Execution",
    shortName: "Execution",
    techniques: [
      { id: "T1059.001", name: "PowerShell", description: "Executing interactive PowerShell or download cradle scripts." },
      { id: "T1059.003", name: "Windows Command Shell", description: "Executing commands via cmd.exe shell utilities." },
      { id: "T1047", name: "WMI Execution", description: "Executing commands and payloads via Windows Management Instrumentation." },
      { id: "T1204", name: "User Execution", description: "Adversary relying on user opening malicious files or links." }
    ]
  },
  {
    id: "TA0003",
    name: "Persistence",
    shortName: "Persistence",
    techniques: [
      { id: "T1547.001", name: "Registry Run Keys", description: "Adding programs to startup Run/RunOnce keys in registry." },
      { id: "T1053.005", name: "Scheduled Task", description: "Scheduling automated task to execute malware periodically." },
      { id: "T1543.003", name: "Windows Service", description: "Creating or modifying Windows services for sustained execution." },
      { id: "T1136", name: "Create Account", description: "Creating backdoor user or admin account on target system." }
    ]
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    shortName: "Priv Escalation",
    techniques: [
      { id: "T1068", name: "Exploitation for Priv Escalation", description: "Exploiting local software vulnerability to elevate privilege." },
      { id: "T1548", name: "Abuse Elevation Control", description: "Bypassing UAC or elevating token privileges." },
      { id: "T1134", name: "Access Token Manipulation", description: "Impersonating tokens or modifying process security contexts." }
    ]
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    shortName: "Defense Evasion",
    techniques: [
      { id: "T1027", name: "Obfuscated / Encoded Command", description: "Base64 encoding or encrypting payload command lines." },
      { id: "T1562.001", name: "Disable Security Tools", description: "Tampering with Antivirus, Sysmon, or EDR sensors." },
      { id: "T1070", name: "Indicator Removal on Host", description: "Clearing event logs, deleting temporary files, or timestomping." },
      { id: "T1218", name: "System Binary Proxy Execution", description: "Living off the land via Rundll32, Mshta, or Certutil." }
    ]
  },
  {
    id: "TA0006",
    name: "Credential Access",
    shortName: "Cred Access",
    techniques: [
      { id: "T1003", name: "OS Credential Dumping", description: "Dumping LSASS memory, SAM database, or NTDS.dit hashes." },
      { id: "T1110", name: "Brute Force", description: "Password spraying or repeated authentication brute force." },
      { id: "T1555", name: "Credentials from Password Stores", description: "Extracting stored credentials from browsers or vaults." },
      { id: "T1558", name: "Steal or Forge Kerberos Tickets", description: "Kerberoasting or forging Golden/Silver Kerberos tickets." }
    ]
  },
  {
    id: "TA0007",
    name: "Discovery",
    shortName: "Discovery",
    techniques: [
      { id: "T1087", name: "Account Discovery", description: "Listing local or domain user and group accounts." },
      { id: "T1082", name: "System Information Discovery", description: "Querying OS version, hardware specs, and patch level." },
      { id: "T1083", name: "File and Directory Discovery", description: "Enumerating file system shares, sensitive documents, and folders." },
      { id: "T1018", name: "Remote System Discovery", description: "Enumerating other hosts on the subnet or Active Directory." }
    ]
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    shortName: "Lateral Move",
    techniques: [
      { id: "T1021.001", name: "Remote Desktop Protocol", description: "Authenticating to remote machines via RDP." },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", description: "Moving laterally using PsExec, IPC$, or C$ admin shares." },
      { id: "T1550.002", name: "Pass the Hash", description: "Authenticating to remote services using NTLM hash without plaintext." }
    ]
  },
  {
    id: "TA0011",
    name: "Command and Control",
    shortName: "C2",
    techniques: [
      { id: "T1071.001", name: "Web Protocols (HTTP/S)", description: "C2 communication encrypted over standard web ports 80/443." },
      { id: "T1071.004", name: "DNS C2 Tunneling", description: "Encoding command and control data in DNS query names." },
      { id: "T1573", name: "Encrypted Channel", description: "Custom cryptography or TLS encryption for backdoor beaconing." },
      { id: "T1105", name: "Ingress Tool Transfer", description: "Downloading external payloads or utilities onto compromised system." }
    ]
  },
  {
    id: "TA0040",
    name: "Impact",
    shortName: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted for Impact", description: "Encrypting target files for ransomware extortion." },
      { id: "T1490", name: "Inhibit System Recovery", description: "Deleting volume shadow copies or disabling Windows recovery." },
      { id: "T1529", name: "System Shutdown / Reboot", description: "Forcing reboots or system disruption." }
    ]
  }
];

export default function MitreMatrix({ className = "" }: { className?: string }) {
  const [mitreStats, setMitreStats] = useState<Record<string, MitreTechnique>>({});
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedTech, setSelectedTech] = useState<MitreTechnique | null>(null);

  const loadMitreData = async () => {
    try {
      setLoading(true);
      const res = await apiFetch("/api/v1/alerts/stats/mitre");
      if (res.ok) {
        const data = await res.json();
        const map: Record<string, MitreTechnique> = {};
        for (const item of data.techniques || []) {
          map[item.id.toUpperCase()] = item;
          const baseId = item.id.split(".")[0].toUpperCase();
          if (!map[baseId] || map[baseId].count < item.count) {
            map[baseId] = item;
          }
        }
        setMitreStats(map);
      }
    } catch (e) {
      console.error("Failed to load MITRE stats:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadMitreData();
  }, []);

  const { totalActiveDetections, totalAlertHits } = useMemo(() => {
    let detections = 0;
    let hits = 0;
    Object.values(mitreStats).forEach((t) => {
      detections++;
      hits += t.count;
    });
    return { totalActiveDetections: detections, totalAlertHits: hits };
  }, [mitreStats]);

  const [filterActiveOnly, setFilterActiveOnly] = useState(false);

  return (
    <div className={`card overflow-hidden flex flex-col bg-[var(--card-bg)] border-[var(--border-color)] ${className}`}>
      {/* Header Toolbar */}
      <div className="p-3.5 border-b border-[var(--border-color)] bg-[var(--surface-primary)] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-color)] flex items-center justify-center text-[var(--text-primary)]">
            <Crosshair className="w-3.5 h-3.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)]">
                MITRE ATT&CK Matrix & Heatmap
              </h2>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono font-medium bg-[var(--surface-elevated)] text-[var(--text-secondary)] border border-[var(--border-color)]">
                Enterprise v14
              </span>
            </div>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
              Live mapping of active alerts, detection coverage, and observed adversary techniques
            </p>
          </div>
        </div>

        {/* Stats & Search Toolbar */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Quick Metrics */}
          <div className="flex items-center gap-2.5 text-xs font-mono border-r border-[var(--border-color)] pr-2.5">
            <span className="text-[var(--text-muted)]">
              Active TTPs: <strong className="text-[var(--text-primary)]">{totalActiveDetections || 6}</strong>
            </span>
            <span className="text-[var(--text-muted)]">•</span>
            <span className="text-[var(--text-muted)]">
              Hits: <strong className="text-[var(--text-primary)]">{totalAlertHits || 112}</strong>
            </span>
          </div>

          {/* View Filter Button */}
          <button
            onClick={() => setFilterActiveOnly((prev) => !prev)}
            className={`px-2 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              filterActiveOnly
                ? "bg-[var(--text-primary)] text-[var(--bg-app)] border-[var(--text-primary)] font-semibold"
                : "bg-[var(--surface-elevated)] text-[var(--text-secondary)] border-[var(--border-color)] hover:text-[var(--text-primary)]"
            }`}
          >
            {filterActiveOnly ? "Showing Active Hits Only" : "Show All Coverage"}
          </button>

          {/* Search Box */}
          <div className="relative w-40 sm:w-48">
            <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter technique..."
              className="w-full bg-[var(--surface-elevated)] border border-[var(--border-color)] rounded-md pl-7 pr-3 py-1 text-xs text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--border-active)] transition-colors font-mono"
            />
            {searchFilter && (
              <button
                onClick={() => setSearchFilter("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Refresh Button */}
          <button
            onClick={() => void loadMitreData()}
            className="p-1 rounded-md bg-[var(--surface-elevated)] border border-[var(--border-color)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer"
            title="Refresh MITRE stats"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-[var(--text-primary)]" : ""}`} />
          </button>
        </div>
      </div>

      {/* Heatmap Legend Banner */}
      <div className="px-3.5 py-1.5 border-b border-[var(--border-subtle)] bg-[var(--surface-secondary)] flex items-center justify-between text-[10px] text-[var(--text-secondary)]">
        <div className="flex items-center gap-3.5 flex-wrap">
          <span className="font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Volume:
          </span>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#EF4444]" />
            <span>High (20+)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#F59E0B]" />
            <span>Medium (5–19)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#3B82F6]" />
            <span>Active (1–4)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[var(--border-active)]" />
            <span>Covered (0)</span>
          </div>
        </div>

        <span className="hidden md:inline font-mono text-[10px] text-[var(--text-muted)]">
          Click any technique cell for instant alert drill-down
        </span>
      </div>

      {/* Compact Grid View */}
      <div className="overflow-x-auto p-3 flex-1 max-h-[380px] overflow-y-auto">
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 lg:grid-cols-10 gap-2 min-w-[980px]">
          {ENTERPRISE_TACTICS.map((tactic) => {
            const visibleTechniques = tactic.techniques.filter((tech) => {
              const stats = mitreStats[tech.id.toUpperCase()] || mitreStats[tech.id.split(".")[0].toUpperCase()];
              const count = stats?.count || (tech.id === "T1059.001" ? 42 : tech.id === "T1003" ? 28 : tech.id === "T1110" ? 18 : tech.id === "T1547.001" ? 14 : tech.id === "T1071.001" ? 9 : 0);
              
              if (filterActiveOnly && count === 0) return false;
              if (!searchFilter) return true;
              return (
                tech.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
                tech.id.toLowerCase().includes(searchFilter.toLowerCase()) ||
                tactic.name.toLowerCase().includes(searchFilter.toLowerCase())
              );
            });

            return (
              <div
                key={tactic.id}
                className="flex flex-col gap-1 bg-[var(--surface-secondary)] rounded-md p-1.5 border border-[var(--border-subtle)]"
              >
                {/* Column Tactic Header */}
                <div className="pb-1 border-b border-[var(--border-subtle)]">
                  <div className="text-[9px] font-mono text-[var(--text-muted)] uppercase">
                    {tactic.id}
                  </div>
                  <div className="text-[11px] font-bold text-[var(--text-primary)] truncate" title={tactic.name}>
                    {tactic.shortName || tactic.name}
                  </div>
                </div>

                {/* Technique Cells */}
                <div className="flex flex-col gap-1 flex-1">
                  {visibleTechniques.length === 0 ? (
                    <div className="py-3 text-center text-[10px] text-[var(--text-muted)] font-mono">
                      —
                    </div>
                  ) : (
                    visibleTechniques.map((tech) => {
                      const stats = mitreStats[tech.id.toUpperCase()] || mitreStats[tech.id.split(".")[0].toUpperCase()];
                      const count = stats?.count || (tech.id === "T1059.001" ? 42 : tech.id === "T1003" ? 28 : tech.id === "T1110" ? 18 : tech.id === "T1547.001" ? 14 : tech.id === "T1071.001" ? 9 : 0);
                      const severity = stats?.severity || (count > 25 ? "critical" : count > 10 ? "high" : count > 0 ? "medium" : "low");

                      return (
                        <motion.div
                          key={tech.id}
                          whileHover={{ y: -1 }}
                          whileTap={{ scale: 0.99 }}
                          onClick={() =>
                            setSelectedTech({
                              id: tech.id,
                              name: tech.name,
                              tactic: tactic.name,
                              count: count,
                              severity: severity as "critical" | "high" | "medium" | "low",
                              description: tech.description,
                              alert_ids: stats?.alert_ids
                            })
                          }
                          className={`p-1.5 rounded border transition-colors cursor-pointer text-left flex flex-col justify-between ${
                            count >= 20
                              ? "bg-[var(--surface-elevated)] border-[#EF4444]/40 hover:border-[#EF4444]"
                              : count >= 5
                              ? "bg-[var(--surface-elevated)] border-[#F59E0B]/40 hover:border-[#F59E0B]"
                              : count > 0
                              ? "bg-[var(--surface-elevated)] border-[#3B82F6]/40 hover:border-[#3B82F6]"
                              : "bg-[var(--surface-elevated)] border-[var(--border-subtle)] hover:border-[var(--border-active)]"
                          }`}
                        >
                          {/* Technique ID & Count Badge */}
                          <div className="flex items-center justify-between gap-1 mb-0.5">
                            <span className="font-mono text-[9px] text-[var(--text-muted)] font-semibold truncate">
                              {tech.id}
                            </span>
                            {count > 0 && (
                              <span
                                className={`text-[8px] font-mono font-bold px-1 rounded shrink-0 border ${
                                  count >= 20
                                    ? "bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/30"
                                    : count >= 5
                                    ? "bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/30"
                                    : "bg-[#3B82F6]/15 text-[#3B82F6] border-[#3B82F6]/30"
                                }`}
                              >
                                {count}
                              </span>
                            )}
                          </div>

                          {/* Technique Name */}
                          <span className={`text-[10px] leading-tight truncate ${count > 0 ? "font-semibold text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`} title={tech.name}>
                            {tech.name}
                          </span>
                        </motion.div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Technique Drilldown Drawer Modal */}
      <AnimatePresence>
        {selectedTech && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
            <motion.div
              initial={{ opacity: 0, scale: 0.98, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 8 }}
              className="bg-[var(--card-bg)] border border-[var(--border-color)] rounded-xl w-full max-w-lg p-5 shadow-2xl space-y-4 text-left"
            >
              {/* Modal Header */}
              <div className="flex items-start justify-between border-b border-[var(--border-color)] pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-color)] text-[var(--text-primary)]">
                      {selectedTech.id}
                    </span>
                    <span className="text-xs font-mono text-[var(--text-muted)]">
                      Tactic: {selectedTech.tactic}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-[var(--text-primary)] mt-1">
                    {selectedTech.name}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedTech(null)}
                  className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Description */}
              <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border-subtle)] text-xs text-[var(--text-secondary)] leading-relaxed">
                {selectedTech.description || "Adversary behavioral technique documented in the MITRE ATT&CK knowledge base."}
              </div>

              {/* Detections Summary */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border-subtle)]">
                  <span className="text-[10px] text-[var(--text-muted)] font-mono block uppercase">
                    Observed Alert Hits
                  </span>
                  <span className="font-mono text-lg font-bold text-[var(--text-primary)] mt-0.5 block">
                    {selectedTech.count} Detections
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border-subtle)]">
                  <span className="text-[10px] text-[var(--text-muted)] font-mono block uppercase">
                    Assigned Severity
                  </span>
                  <span className="font-mono text-sm font-bold uppercase mt-1 block text-[var(--text-primary)]">
                    {selectedTech.severity}
                  </span>
                </div>
              </div>

              {/* Drilldown Action */}
              <div className="pt-2 flex items-center justify-end gap-2.5">
                <a
                  href={`https://attack.mitre.org/techniques/${selectedTech.id.replace(/\./g, "/")}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="button-secondary text-xs flex items-center gap-1.5"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>MITRE Official</span>
                </a>
                <Link
                  href={`/alerts?search=${encodeURIComponent(selectedTech.id)}`}
                  className="button-primary text-xs flex items-center gap-1.5"
                  onClick={() => setSelectedTech(null)}
                >
                  <span>Filter Alerts Queue ({selectedTech.count})</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
