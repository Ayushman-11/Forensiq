"use client";

import React, { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Terminal, 
  Server, 
  Globe, 
  FileCode, 
  ShieldAlert, 
  Play, 
  RotateCcw, 
  Copy, 
  Check, 
  ChevronRight, 
  ZoomIn, 
  ZoomOut, 
  Maximize2,
  Cpu,
  User,
  Hash,
  AlertTriangle
} from "lucide-react";
import type { AlertRecord } from "@/lib/types";
import IocHoverCard from "@/components/enrichment/IocHoverCard";
import { noVerdictLabel } from "@/lib/types";

export interface ProcessNode {
  id: string;
  name: string;
  pid?: number | string;
  parentPid?: number | string;
  user?: string;
  commandLine?: string;
  type: "root" | "execution" | "child" | "network" | "artifact";
  threatLevel: "benign" | "suspicious" | "malicious";
  mitreTechnique?: string;
  timestamp?: string;
  details?: Record<string, string | undefined>;
  children?: ProcessNode[];
}

interface ProcessTreeGraphProps {
  alert: AlertRecord;
  className?: string;
}

export default function ProcessTreeGraph({ alert, className = "" }: ProcessTreeGraphProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Evidence-only tree: every node and value comes from a field on the alert. Nothing is inferred
  // or filled in; a missing parent or process shows as the host / detection itself.
  const treeData = useMemo<ProcessNode>(() => {
    const ctx = (alert.context || {}) as Record<string, any>;
    const raw = (alert.raw_event || alert.raw_alert_data?.content || {}) as Record<string, any>;
    const pick = (...values: unknown[]): string | undefined => {
      for (const v of values) {
        if (v !== undefined && v !== null && String(v).trim() !== "") return String(v);
      }
      return undefined;
    };
    const baseName = (path?: string) => (path ? path.split("\\").pop() || path : undefined);
    const enrichmentFor = (ioc?: string) =>
      ioc ? (alert.enrichments || []).find((e) => e.ioc === ioc && !noVerdictLabel(e)) : undefined;
    const levelFor = (ioc?: string): ProcessNode["threatLevel"] => {
      const rep = enrichmentFor(ioc)?.reputation;
      if (rep === "malicious") return "malicious";
      if (rep === "benign") return "benign";
      return "suspicious";
    };

    const host = pick(alert.host, ctx.host, raw.host, raw.ComputerName);
    const user = pick(alert.user, ctx.user, raw.User, raw.TargetUserName, raw.SubjectUserName);
    const eventCode = pick(alert.event_code, raw.EventCode);
    const techniques = (alert.mitre_mappings || []).map((m) => m.technique).filter(Boolean) as string[];
    const tech = pick(alert.mitre_technique, techniques[0]);
    const when = alert.created_at;

    const parentPath = pick(alert.parent_process, ctx.parent_process, raw.ParentImage, raw.ParentProcessName);
    const parentPid = pick(ctx.parent_process_id, raw.ParentProcessId);
    const parentCmd = pick(raw.ParentCommandLine);
    const procPath = pick(alert.process_name, ctx.process_name, raw.Image, raw.NewProcessName);
    const procPid = pick(ctx.process_id, raw.ProcessId, raw.NewProcessId);
    const cmd = pick(alert.command_line, ctx.command_line, raw.CommandLine, raw.ProcessCommandLine);

    const children: ProcessNode[] = [];
    const dns = pick(alert.dns_query, ctx.dns_query, raw.QueryName);
    if (dns) {
      children.push({
        id: `dns-${alert._id}`, name: `DNS query: ${dns}`, type: "network", threatLevel: levelFor(dns),
        commandLine: dns, timestamp: when,
        details: { QueryName: dns, QueryResults: pick(raw.QueryResults), Source: "dns_query field" },
      });
    }
    const destIp = pick(alert.dest_ip, ctx.dest_ip, raw.DestinationIp);
    if (destIp) {
      const port = pick(alert.dest_port, ctx.dest_port, raw.DestinationPort);
      const target = port ? `${destIp}:${port}` : destIp;
      children.push({
        id: `net-${alert._id}`, name: `Connection: ${target}`, type: "network", threatLevel: levelFor(destIp),
        commandLine: target, timestamp: when,
        details: { Destination: target, Protocol: pick(alert.protocol, raw.Protocol), Source: "dest_ip field" },
      });
    }
    const srcIp = pick(alert.source_ip, ctx.source_ip, raw.IpAddress, raw.SourceIp);
    if (srcIp) {
      children.push({
        id: `src-${alert._id}`, name: `Source address: ${srcIp}`, type: "network", threatLevel: levelFor(srcIp),
        commandLine: srcIp, timestamp: when,
        details: { SourceIP: srcIp, LogonType: pick(raw.LogonType), Status: pick(raw.Status, raw.FailureReason), Source: "source_ip field" },
      });
    }
    const regKey = pick(alert.registry_key, ctx.registry_key, raw.TargetObject);
    if (regKey) {
      const regVal = pick(alert.registry_details, ctx.registry_details, raw.Details);
      children.push({
        id: `reg-${alert._id}`, name: `Registry: ${baseName(regKey)}`, type: "artifact", threatLevel: "suspicious",
        commandLine: regVal ? `${regKey} = ${regVal}` : regKey, timestamp: when,
        details: { RegistryKey: regKey, Value: regVal, Source: "registry_key field" },
      });
    }
    const hashes = pick(alert.hashes, raw.Hashes);
    if (hashes) {
      children.push({
        id: `hash-${alert._id}`, name: "File hashes", type: "artifact", threatLevel: "suspicious",
        commandLine: hashes, timestamp: when, details: { Hashes: hashes, Source: "hashes field" },
      });
    }

    const execution: ProcessNode = {
      id: `exec-${alert._id}`,
      name: baseName(procPath) || `Detection: ${alert.rule_name || alert.title}`,
      pid: procPid,
      parentPid,
      user,
      type: "execution",
      threatLevel: alert.severity?.toLowerCase() === "low" ? "suspicious" : "malicious",
      mitreTechnique: tech,
      commandLine: cmd,
      timestamp: when,
      details: {
        Image: procPath,
        Host: host,
        RuleName: alert.rule_name || alert.title,
        EventCode: eventCode,
        Techniques: techniques.length ? techniques.join(", ") : undefined,
      },
      children,
    };

    return {
      id: `root-${alert._id}`,
      name: baseName(parentPath) || (host ? `Host: ${host}` : "Parent process not recorded"),
      pid: parentPid,
      user,
      type: "root",
      threatLevel: "benign",
      commandLine: parentCmd,
      timestamp: when,
      details: { Image: parentPath, Host: host, Note: parentPath ? undefined : "The event carries no parent process" },
      children: [execution],
    };
  }, [alert]);

  // Flatten nodes for step-by-step playback
  const flattenedNodes = useMemo(() => {
    const list: ProcessNode[] = [];
    const traverse = (n: ProcessNode) => {
      list.push(n);
      if (n.children) {
        n.children.forEach(traverse);
      }
    };
    traverse(treeData);
    return list;
  }, [treeData]);

  // Reset selected node whenever the active alert or treeData changes
  useEffect(() => {
    if (flattenedNodes.length > 1) {
      setSelectedNodeId(flattenedNodes[1].id);
    } else if (flattenedNodes.length > 0) {
      setSelectedNodeId(flattenedNodes[0].id);
    }
    setActiveStep(0);
    setIsPlaying(false);
  }, [alert._id]);

  // Handle Playback Simulation
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isPlaying) {
      timer = setInterval(() => {
        setActiveStep((prev) => {
          const next = prev + 1;
          if (next >= flattenedNodes.length) {
            setIsPlaying(false);
            return prev;
          }
          setSelectedNodeId(flattenedNodes[next].id);
          return next;
        });
      }, 900);
    }
    return () => clearInterval(timer);
  }, [isPlaying, flattenedNodes]);

  const selectedNode = useMemo(() => {
    return flattenedNodes.find((n) => n.id === selectedNodeId) || flattenedNodes[0];
  }, [flattenedNodes, selectedNodeId]);

  const copyCommandLine = () => {
    if (selectedNode?.commandLine) {
      navigator.clipboard.writeText(selectedNode.commandLine);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  const restartPlayback = () => {
    setActiveStep(0);
    setSelectedNodeId(flattenedNodes[0].id);
    setIsPlaying(true);
  };

  return (
    <div className={`card overflow-hidden flex flex-col bg-[var(--card-bg)] border-[var(--border-color)] ${className}`}>
      {/* Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between border-b border-[var(--border-color)] bg-[var(--surface-primary)] p-3.5 gap-3 shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-color)] flex items-center justify-center text-[var(--text-primary)]">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <span>Process Execution Tree & Attack Flow</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30 font-mono">
                {treeData.children?.[0]?.details?.EventCode || (alert.event_code ? `Event ${alert.event_code}` : "Process Flow")}
              </span>
            </h3>
            <p className="text-[11px] text-[var(--text-muted)]">
              Interactive parent-child lineage, spawned sub-processes, and network telemetry
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={isPlaying ? () => setIsPlaying(false) : restartPlayback}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              isPlaying
                ? "bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30"
                : "button-secondary"
            }`}
          >
            {isPlaying ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isPlaying ? "Simulating..." : "Play Execution"}</span>
          </button>

          <div className="flex items-center bg-[var(--surface-elevated)] border border-[var(--border-color)] rounded-lg p-0.5">
            <button
              onClick={() => setZoomLevel((z) => Math.max(0.8, z - 0.1))}
              className="p-1.5 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[10px] font-mono text-[var(--text-secondary)] px-1.5">
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => setZoomLevel((z) => Math.min(1.3, z + 0.1))}
              className="p-1.5 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="p-1.5 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors border-l border-[var(--border-color)] cursor-pointer"
              title="Reset View"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Workspace (Graph Canvas on Top/Left, Node Inspector on Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] divide-y lg:divide-y-0 lg:divide-x divide-[var(--border-color)] min-h-[460px]">
        {/* Interactive Visual Graph Canvas */}
        <div className="p-6 overflow-auto bg-[var(--surface-secondary)] relative flex flex-col justify-center">
          <div
            className="transition-transform duration-200 origin-top-left"
            style={{ transform: `scale(${zoomLevel})` }}
          >
            {/* Level 0: Root Process */}
            <div className="flex flex-col items-center">
              <NodeCard
                node={treeData}
                isSelected={selectedNodeId === treeData.id}
                onSelect={() => setSelectedNodeId(treeData.id)}
              />

              {/* Connecting Stem */}
              <div className="w-0.5 h-8 bg-[var(--border-active)] my-1 relative">
                <span className="absolute -left-1 top-1/2 -translate-y-1/2 w-2.5 h-2.5 rounded-full bg-[#EF4444] animate-ping opacity-60" />
              </div>

              {/* Level 1: Primary Execution Node */}
              {treeData.children?.[0] && (
                <div className="flex flex-col items-center w-full">
                  <NodeCard
                    node={treeData.children[0]}
                    isSelected={selectedNodeId === treeData.children[0].id}
                    onSelect={() => setSelectedNodeId(treeData.children![0].id)}
                  />

                  {/* Dynamic Connecting Branching SVG */}
                  {treeData.children[0].children && treeData.children[0].children.length > 0 && (
                    <div className="relative w-full max-w-[620px] h-12 my-1">
                      <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 600 50">
                        {treeData.children[0].children.length === 1 && (
                          <path
                            d="M 300 0 L 300 50"
                            fill="none"
                            stroke="var(--border-active)"
                            strokeWidth="2"
                          />
                        )}
                        {treeData.children[0].children.length === 2 && (
                          <>
                            <path
                              d="M 300 0 L 300 20 L 160 20 L 160 50"
                              fill="none"
                              stroke="#F59E0B"
                              strokeWidth="1.5"
                              strokeDasharray="4 3"
                            />
                            <path
                              d="M 300 0 L 300 20 L 440 20 L 440 50"
                              fill="none"
                              stroke="#EF4444"
                              strokeWidth="1.5"
                            />
                          </>
                        )}
                        {treeData.children[0].children.length >= 3 && (
                          <>
                            <path
                              d="M 300 0 L 300 20 L 100 20 L 100 50"
                              fill="none"
                              stroke="#F59E0B"
                              strokeWidth="1.5"
                              strokeDasharray="4 3"
                            />
                            <path
                              d="M 300 0 L 300 50"
                              fill="none"
                              stroke="#EF4444"
                              strokeWidth="2"
                            />
                            <path
                              d="M 300 0 L 300 20 L 500 20 L 500 50"
                              fill="none"
                              stroke="#8B5CF6"
                              strokeWidth="1.5"
                              strokeDasharray="4 3"
                            />
                          </>
                        )}
                      </svg>
                    </div>
                  )}

                  {/* Level 2: Child Artifacts / Recon / Network Hops / Credential Dumps */}
                  <div className={`grid gap-4 w-full max-w-[700px] ${
                    treeData.children[0].children?.length === 1
                      ? "grid-cols-1 max-w-[300px]"
                      : treeData.children[0].children?.length === 2
                      ? "grid-cols-1 sm:grid-cols-2 max-w-[520px]"
                      : "grid-cols-1 sm:grid-cols-2 md:grid-cols-3 max-w-[700px]"
                  }`}>
                    {treeData.children[0].children?.map((child) => (
                      <div key={child.id} className="flex justify-center">
                        <NodeCard
                          node={child}
                          isSelected={selectedNodeId === child.id}
                          onSelect={() => setSelectedNodeId(child.id)}
                          isSubNode
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Node Inspector Drawer */}
        <div className="p-4 bg-[var(--surface-primary)] flex flex-col gap-4 overflow-y-auto">
          <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)]">
                Process Telemetry Inspector
              </span>
            </div>
            <span
              className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                selectedNode.threatLevel === "malicious"
                  ? "bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/30"
                  : selectedNode.threatLevel === "suspicious"
                  ? "bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/30"
                  : "bg-[#22C55E]/15 text-[#22C55E] border-[#22C55E]/30"
              }`}
            >
              {selectedNode.threatLevel}
            </span>
          </div>

          {/* Node Summary */}
          <div className="space-y-3">
            <div>
              <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                Process Name
              </span>
              <div className="font-mono text-sm font-bold text-[var(--text-primary)] flex items-center gap-1.5 mt-0.5">
                <Terminal className="w-4 h-4 text-[var(--text-secondary)]" />
                <span>{selectedNode.name}</span>
              </div>
            </div>

            {/* PID & Identity Grid */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)]">
                <span className="text-[10px] font-mono text-[var(--text-muted)] block uppercase">PID / PPID</span>
                <span className="font-mono font-bold text-[var(--text-primary)] mt-0.5 block">
                  {selectedNode.pid || "—"} {selectedNode.parentPid ? `(Parent: ${selectedNode.parentPid})` : ""}
                </span>
              </div>
              <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)]">
                <span className="text-[10px] font-mono text-[var(--text-muted)] block uppercase">Security Context</span>
                <span className="font-mono font-bold text-[var(--text-primary)] mt-0.5 block truncate">
                  {selectedNode.user || alert.user || "SYSTEM"}
                </span>
              </div>
            </div>

            {/* MITRE Technique Badge if mapped */}
            {selectedNode.mitreTechnique && (
              <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider">
                  ATT&CK Technique
                </span>
                <span className="font-mono text-xs font-bold text-[#EF4444] bg-[#EF4444]/15 px-2 py-0.5 rounded border border-[#EF4444]/30">
                  {selectedNode.mitreTechnique}
                </span>
              </div>
            )}

            {/* Command Line with 1-Click Copy */}
            {selectedNode.commandLine && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">
                    Full Execution Command Line
                  </span>
                  <button
                    onClick={copyCommandLine}
                    className="flex items-center gap-1 text-[10px] text-[var(--text-primary)] hover:underline transition-colors cursor-pointer"
                  >
                    {copiedCmd ? (
                      <>
                        <Check className="w-3 h-3 text-[#22C55E]" />
                        <span className="text-[#22C55E] font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3 text-[var(--text-muted)]" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)] font-mono text-[11px] text-[var(--text-primary)] break-all select-all leading-relaxed max-h-36 overflow-y-auto">
                  {selectedNode.commandLine}
                </div>
              </div>
            )}

            {/* Extra Telemetry Details */}
            {selectedNode.details && Object.keys(selectedNode.details).length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                  Associated Telemetry Attributes
                </span>
                <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-1.5 text-xs font-mono">
                  {Object.entries(selectedNode.details).map(([k, v]) => (
                    <div key={k} className="flex justify-between items-center text-[11px]">
                      <span className="text-[var(--text-muted)]">{k}:</span>
                      <span className="text-[var(--text-primary)] font-semibold truncate max-w-[190px]">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Subcomponent for each node card in the SVG tree
function NodeCard({
  node,
  isSelected,
  onSelect,
  isSubNode = false,
}: {
  node: ProcessNode;
  isSelected: boolean;
  onSelect: () => void;
  isSubNode?: boolean;
}) {
  const isMalicious = node.threatLevel === "malicious";
  const isSuspicious = node.threatLevel === "suspicious";

  const IconComponent =
    node.type === "network"
      ? Globe
      : node.type === "artifact"
      ? FileCode
      : node.type === "root"
      ? Server
      : Terminal;

  return (
    <motion.div
      whileHover={{ y: -1 }}
      whileTap={{ scale: 0.99 }}
      onClick={onSelect}
      className={`cursor-pointer rounded-lg p-3 border transition-colors text-left select-none ${
        isSubNode ? "w-52" : "w-64"
      } ${
        isSelected
          ? "bg-[var(--surface-elevated)] border-[var(--text-primary)] ring-1 ring-[var(--text-primary)]"
          : isMalicious
          ? "bg-[var(--surface-secondary)] border-[#EF4444]/40 hover:border-[#EF4444]"
          : isSuspicious
          ? "bg-[var(--surface-secondary)] border-[#F59E0B]/40 hover:border-[#F59E0B]"
          : "bg-[var(--surface-secondary)] border-[var(--border-subtle)] hover:border-[var(--border-active)]"
      }`}
    >
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-1.5">
          <div
            className={`w-6 h-6 rounded-md flex items-center justify-center ${
              isMalicious
                ? "bg-[#EF4444]/15 text-[#EF4444]"
                : isSuspicious
                ? "bg-[#F59E0B]/15 text-[#F59E0B]"
                : "bg-[var(--surface-elevated)] text-[var(--text-secondary)]"
            }`}
          >
            <IconComponent className="w-3.5 h-3.5" />
          </div>
          <span className="text-[9px] font-mono uppercase text-[var(--text-muted)]">
            {node.type}
          </span>
        </div>
        {node.mitreTechnique && (
          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30 font-bold">
            {node.mitreTechnique}
          </span>
        )}
      </div>

      <div className="font-mono text-xs font-bold text-[var(--text-primary)] truncate">
        {node.name}
      </div>

      <div className="flex items-center justify-between text-[10px] font-mono text-[var(--text-muted)] mt-2 pt-2 border-t border-[var(--border-subtle)]">
        <span>PID: {node.pid || "—"}</span>
        <span className="text-[9px] text-[var(--text-primary)] font-semibold">Inspect &rarr;</span>
      </div>
    </motion.div>
  );
}
