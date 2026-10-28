"use client";

import React, { useEffect, useState, useRef } from "react";
import {
  CheckCircle2,
  Loader2,
  X,
  ShieldAlert,
  Search,
  Database,
  Network,
  Crosshair,
  Clock,
  Sparkles,
  CheckCheck,
  Terminal,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  Radio,
  Wifi,
  Download,
  FileDown,
} from "lucide-react";
import { apiFetch } from "@/lib/api";

import { API_BASE, getAccessToken } from "@/lib/auth";
import { engineLabel, type AlertRecord, type PipelineStep, type StepStatus } from "@/lib/types";
import ProcessTreeGraph from "@/components/investigation/ProcessTreeGraph";

const INITIAL_STEPS: PipelineStep[] = [
  {
    step: 1,
    node: "extract_context",
    name: "Context Extraction",
    description: "Extracting host, user, and IOC indicators from raw telemetry",
    status: "pending",
  },
  {
    step: 2,
    node: "enrich_iocs",
    name: "Threat Intel & Cache Lookup",
    description: "Enriching IOCs via VirusTotal & AbuseIPDB with MongoDB cache optimization",
    status: "pending",
  },
  {
    step: 3,
    node: "correlate_events",
    name: "Historical Event Correlation",
    description: "Searching tenant detection history for shared entities and patterns",
    status: "pending",
  },
  {
    step: 4,
    node: "map_mitre",
    name: "MITRE ATT&CK Mapping",
    description: "Classifying behavioral heuristics to MITRE tactics and techniques",
    status: "pending",
  },
  {
    step: 5,
    node: "build_timeline",
    name: "Attack Timeline Assembly",
    description: "Synthesizing multi-source events chronologically across 5 cyber phases",
    status: "pending",
  },
  {
    step: 6,
    node: "assess_risk",
    name: "Risk Assessment",
    description: "Scoring threat impact, confidence, and blast radius (LLM when configured, otherwise rules engine)",
    status: "pending",
  },
  {
    step: 7,
    node: "generate_recommendations",
    name: "Incident Response Playbook",
    description: "Formulating containment, eradication, and verification checklists",
    status: "pending",
  },
];

const NODE_ICONS: Record<string, React.ReactNode> = {
  extract_context: <Search className="w-4 h-4" />,
  enrich_iocs: <Database className="w-4 h-4" />,
  correlate_events: <Network className="w-4 h-4" />,
  map_mitre: <Crosshair className="w-4 h-4" />,
  build_timeline: <Clock className="w-4 h-4" />,
  assess_risk: <ShieldAlert className="w-4 h-4" />,
  generate_recommendations: <Sparkles className="w-4 h-4" />,
};

interface InvestigationModalProps {
  alert: AlertRecord;
  isOpen: boolean;
  onClose: () => void;
  onComplete: (updatedAlert: AlertRecord) => void;
}

export default function InvestigationModal({
  alert,
  isOpen,
  onClose,
  onComplete,
}: InvestigationModalProps) {
  const [steps, setSteps] = useState<PipelineStep[]>(INITIAL_STEPS);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [isFinished, setIsFinished] = useState(false);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [showLogs, setShowLogs] = useState(true);
  const [finalAlert, setFinalAlert] = useState<AlertRecord | null>(null);
  const [transport, setTransport] = useState<"connecting" | "websocket" | "sse">("connecting");
  const [elapsedMs, setElapsedMs] = useState(0);
  const [expandedStep, setExpandedStep] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState<boolean>(false);
  const [activeModalTab, setActiveModalTab] = useState<"pipeline" | "tree">("pipeline");

  const logsEndRef = useRef<HTMLDivElement | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const startTimeRef = useRef<number>(Date.now());
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const completedRef = useRef<boolean>(false);

  // Auto-scroll logs
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  // Elapsed timer loop
  useEffect(() => {
    if (!isOpen) return;

    if (!isFinished && !streamError) {
      startTimeRef.current = Date.now();
      timerRef.current = setInterval(() => {
        setElapsedMs(Date.now() - startTimeRef.current);
      }, 100);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isOpen, isFinished, streamError]);

  // Main Streaming Lifecycle: WebSocket with Automatic SSE Fallback
  useEffect(() => {
    if (!isOpen) return;

    // Reset state for new investigation run
    completedRef.current = false;
    setSteps(INITIAL_STEPS.map((s, idx) => ({ ...s, status: idx === 0 ? "running" : "pending" })));
    setCurrentStepIndex(0);
    setIsFinished(false);
    setStreamError(null);
    setFinalAlert(null);
    setTransport("connecting");
    setLogs([`[${new Date().toLocaleTimeString()}] Initializing AI agent investigation pipeline for alert: ${alert.title}`]);

    let isCancelled = false;
    const controller = new AbortController();
    abortControllerRef.current = controller;

    function buildWebSocketUrl(): string {
      const token = getAccessToken() || "";
      let base = API_BASE;
      if (typeof window !== "undefined" && !base.startsWith("http")) {
        base = `${window.location.protocol}//${window.location.host}${base}`;
      }
      const wsBase = base.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
      return `${wsBase}/api/v1/alerts/${encodeURIComponent(alert._id)}/ws?token=${encodeURIComponent(token)}`;
    }

    async function startSSEFallback() {
      if (isCancelled || completedRef.current) return;
      setTransport("sse");
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] [Transport] Establishing Server-Sent Events (SSE) push stream...`,
      ]);

      try {
        const response = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alert._id)}/investigate/stream`, {
          method: "POST",
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Server returned status ${response.status}: ${response.statusText}`);
        }

        if (!response.body) {
          throw new Error("ReadableStream not supported by response body.");
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const messages = buffer.split("\n\n");
          buffer = messages.pop() ?? "";

          for (const rawMessage of messages) {
            if (!rawMessage.trim()) continue;

            let eventType = "message";
            let dataStr = "";

            for (const line of rawMessage.split("\n")) {
              if (line.startsWith("event:")) {
                eventType = line.replace("event:", "").trim();
              } else if (line.startsWith("data:")) {
                dataStr = line.replace("data:", "").trim();
              }
            }

            if (!dataStr) continue;

            try {
              const payload = JSON.parse(dataStr);
              handleStreamEvent(eventType, payload);
            } catch (err) {
              console.warn("Could not parse SSE JSON payload:", dataStr, err);
            }
          }
        }
      } catch (err: unknown) {
        if (err instanceof Error && err.name === "AbortError") {
          return;
        }
        const errorMsg = err instanceof Error ? err.message : "Stream connection terminated unexpectedly";
        setStreamError(errorMsg);
        setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ERROR: ${errorMsg}`]);
      }
    }

    function initWebSocket() {
      try {
        const wsUrl = buildWebSocketUrl();
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        let pingInterval: NodeJS.Timeout | null = null;

        ws.onopen = () => {
          if (isCancelled) {
            ws.close();
            return;
          }
          setTransport("websocket");
          setLogs((prev) => [
            ...prev,
            `[${new Date().toLocaleTimeString()}] [WebSocket] Connected to real-time agent pipeline stream.`,
          ]);

          // Keep alive ping
          pingInterval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ action: "ping" }));
            }
          }, 20000);
        };

        ws.onmessage = (event) => {
          if (isCancelled) return;
          try {
            const parsed = JSON.parse(event.data);
            const eventType = parsed.event || "message";
            const eventData = parsed.data || {};
            handleStreamEvent(eventType, eventData);
          } catch (err) {
            console.warn("WebSocket parse error:", err, event.data);
          }
        };

        ws.onerror = (err) => {
          if (isCancelled || completedRef.current) return;
          console.warn("WebSocket stream error, transitioning to SSE fallback:", err);
          if (pingInterval) clearInterval(pingInterval);
          // Fall back seamlessly to SSE
          void startSSEFallback();
        };

        ws.onclose = (ev) => {
          if (pingInterval) clearInterval(pingInterval);
          if (isCancelled) return;

          // If closed prematurely without completion and without normal close, fall back to SSE
          if (!completedRef.current && ev.code !== 1000) {
            console.warn(`WebSocket closed with code ${ev.code}. Triggering SSE fallback.`);
            void startSSEFallback();
          }
        };
      } catch (err) {
        console.warn("WebSocket initialization failed, falling back to SSE:", err);
        void startSSEFallback();
      }
    }

    // Attempt WebSocket connection first
    initWebSocket();

    return () => {
      isCancelled = true;
      controller.abort();
      if (wsRef.current) {
        wsRef.current.close(1000, "Modal closed");
        wsRef.current = null;
      }
    };
  }, [isOpen, alert._id, alert.title]);

  function handleStreamEvent(eventType: string, data: any) {
    const time = new Date().toLocaleTimeString();

    if (eventType === "connected") {
      setLogs((prev) => [
        ...prev,
        `[${time}] Pipeline session established for alert ${data.alert_id ?? alert._id}.`,
      ]);
    } else if (eventType === "status") {
      setLogs((prev) => [
        ...prev,
        `[${time}] [Status] ${data.message || data.status}`,
      ]);
    } else if (eventType === "init") {
      setLogs((prev) => [
        ...prev,
        `[${time}] Pipeline initialized. Job ID: ${data.job_id}. 7 Specialized nodes queued.`,
      ]);
    } else if (eventType === "node_complete") {
      const completedNode = data.node;
      const summary = data.summary || "Agent task completed.";

      setLogs((prev) => [
        ...prev,
        `[${time}] Completed ${data.name}: ${summary}`,
      ]);

      setSteps((prevSteps) => {
        const nextSteps = prevSteps.map((s) => {
          if (s.node === completedNode) {
            return {
              ...s,
              status: "completed" as StepStatus,
              summary: summary,
              data: data.data,
            };
          }
          return s;
        });

        // Set the next pending step to running
        const nextPendingIdx = nextSteps.findIndex((s) => s.status === "pending");
        if (nextPendingIdx !== -1) {
          nextSteps[nextPendingIdx].status = "running";
          setCurrentStepIndex(nextPendingIdx);
        } else {
          setCurrentStepIndex(nextSteps.length);
        }

        return nextSteps;
      });
    } else if (eventType === "complete") {
      completedRef.current = true;
      setIsFinished(true);
      const updated = data.alert as AlertRecord;
      setFinalAlert(updated);
      setLogs((prev) => [
        ...prev,
        `[${time}] Pipeline investigation complete! Risk Score: ${updated?.risk_score ?? "N/A"}/100, Confidence: ${updated?.ai_confidence ?? "N/A"}% (${engineLabel(updated?.engines?.risk)}).`,
      ]);
      if (updated) {
        onComplete(updated);
      }
    } else if (eventType === "error") {
      setStreamError(data.error || "Investigation failed");
      setLogs((prev) => [...prev, `[${time}] Pipeline error: ${data.error}`]);
    }
  }

  function handleReinvestigate() {
    setSteps(INITIAL_STEPS.map((s, idx) => ({ ...s, status: idx === 0 ? "running" : "pending" })));
    setCurrentStepIndex(0);
    setIsFinished(false);
    setStreamError(null);
    setFinalAlert(null);
    completedRef.current = false;
    startTimeRef.current = Date.now();
    setLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] Triggering fresh re-investigation via live stream...`,
    ]);

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: "reinvestigate" }));
    } else {
      // Re-trigger via SSE if socket not active
      void (async () => {
        try {
          const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alert._id)}/investigate/stream`, {
            method: "POST",
          });
          if (res.ok && res.body) {
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buf = "";
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buf += decoder.decode(value, { stream: true });
              const msgs = buf.split("\n\n");
              buf = msgs.pop() ?? "";
              for (const m of msgs) {
                if (!m.trim()) continue;
                let ev = "message";
                let ds = "";
                for (const l of m.split("\n")) {
                  if (l.startsWith("event:")) ev = l.replace("event:", "").trim();
                  else if (l.startsWith("data:")) ds = l.replace("data:", "").trim();
                }
                if (ds) handleStreamEvent(ev, JSON.parse(ds));
              }
            }
          }
        } catch (e: any) {
          setStreamError(e.message || "Failed to restart stream");
        }
      })();
    }
  }

  const downloadPdf = async (type: "full" | "executive" = "full") => {
    setDownloadingPdf(true);
    try {
      const endpoint = `/api/v1/alerts/${encodeURIComponent(alert._id)}/report/pdf?report_type=${type}`;
      const response = await apiFetch(endpoint);
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || "PDF report generation failed");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forensiq_${type === "full" ? "investigation_report" : "executive_summary"}_${alert._id.slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      console.error("PDF download failed:", err);
      if (typeof window !== "undefined") {
        window.alert(err instanceof Error ? err.message : "Failed to download PDF report");
      }
    } finally {

      setDownloadingPdf(false);
    }
  };

  if (!isOpen) return null;

  const completedCount = steps.filter((s) => s.status === "completed").length;
  const progressPercent = Math.min(100, Math.round((completedCount / steps.length) * 100));
  const elapsedFormatted = (elapsedMs / 1000).toFixed(1) + "s";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative flex flex-col w-full max-w-4xl max-h-[92vh] bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-6 py-4 bg-[var(--color-surface-2)]">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-[var(--color-accent)]/10 border border-[var(--color-accent)]/30 text-[var(--color-accent)]">
              {isFinished ? (
                <CheckCheck className="w-5 h-5 text-[var(--color-success)]" />
              ) : streamError ? (
                <AlertTriangle className="w-5 h-5 text-[var(--color-red)]" />
              ) : (
                <Loader2 className="w-5 h-5 animate-spin" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--color-accent)] font-semibold">
                  LangGraph Live Pipeline
                </span>
                <span className="text-[var(--color-text-dim)]">•</span>
                <span className="font-mono text-[11px] text-[var(--color-text-muted)]">
                  {alert.host ?? "Host"} ({alert.user ?? "User"})
                </span>
                <span className="text-[var(--color-text-dim)]">•</span>
                {/* Real-time Streaming Transport Protocol Badge */}
                {transport === "websocket" ? (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold shadow-xs">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    WebSocket Live
                  </span>
                ) : transport === "sse" ? (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-semibold shadow-xs">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    SSE Stream
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30 font-semibold">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
                    Connecting...
                  </span>
                )}
              </div>
              <h2 className="text-base font-bold text-[var(--color-text)] truncate max-w-lg">
                {alert.title}
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {(isFinished || streamError) && (
              <button
                onClick={handleReinvestigate}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-[var(--color-accent)] bg-[var(--color-accent)]/10 hover:bg-[var(--color-accent)]/20 border border-[var(--color-accent)]/30 transition-all cursor-pointer"
                title="Re-run pipeline investigation"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Re-investigate</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-surface-3)] transition-colors cursor-pointer"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Progress bar banner */}
        <div className="border-b border-[var(--color-border)] px-6 py-3 bg-[var(--color-surface)]">
          <div className="flex items-center justify-between text-xs mb-1.5 font-mono">
            <span className="text-[var(--color-text-muted)] flex items-center gap-2">
              <span>Investigation Progress:</span>
              <strong className="text-[var(--color-accent)]">{progressPercent}%</strong>
              <span className="text-[var(--color-text-dim)]">
                ({completedCount} of {steps.length} nodes finished)
              </span>
              <span className="text-[var(--color-text-dim)]">•</span>
              <span className="text-[var(--color-text-dim)]">Time: {elapsedFormatted}</span>
            </span>
            <span className="text-[var(--color-text-muted)]">
              {isFinished ? (
                <span className="text-[var(--color-success)] font-semibold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Pipeline Finished
                </span>
              ) : streamError ? (
                <span className="text-[var(--color-red)] font-semibold">Execution Halted</span>
              ) : (
                <span className="text-[var(--color-accent)] animate-pulse flex items-center gap-1.5">
                  <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-ping" />
                  Streaming live agent telemetry...
                </span>
              )}
            </span>
          </div>
          <div className="w-full h-1.5 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-[var(--color-accent)] to-[var(--color-success)] transition-all duration-300 ease-out"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* Body content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-3">
          {/* Tab Selector */}
          <div className="flex items-center gap-2 border-b border-[var(--color-border)] pb-3 mb-2">
            <button
              onClick={() => setActiveModalTab("pipeline")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeModalTab === "pipeline"
                  ? "bg-[var(--color-surface-3)] text-white border border-[var(--color-border)] font-bold shadow-sm"
                  : "text-[var(--color-text-muted)] hover:text-white"
              }`}
            >
              Pipeline Execution Steps (7 Nodes)
            </button>
            <button
              onClick={() => setActiveModalTab("tree")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                activeModalTab === "tree"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-sm"
                  : "text-[var(--color-text-muted)] hover:text-cyan-300"
              }`}
            >
              <span>Visual Process Execution Tree</span>
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 uppercase font-mono font-bold">
                Graph
              </span>
            </button>
          </div>

          {streamError && (
            <div className="p-4 rounded-lg bg-[var(--color-red)]/10 border border-[var(--color-red)]/30 text-[var(--color-red)] text-sm flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Pipeline Execution Warning</p>
                <p className="text-xs opacity-90 mt-1">{streamError}</p>
              </div>
            </div>
          )}

          {activeModalTab === "tree" ? (
            <div className="space-y-3">
              <ProcessTreeGraph alert={finalAlert || alert} />
            </div>
          ) : (
            /* Stepper list */
            <div className="space-y-2">
              {steps.map((s, idx) => {
                const isRunning = s.status === "running";
                const isCompleted = s.status === "completed";
                const isExpanded = expandedStep === s.node;

              return (
                <div
                  key={s.node}
                  className={`p-3.5 rounded-lg border transition-all ${
                    isRunning
                      ? "bg-[var(--color-surface-2)] border-[var(--color-accent)]/60 shadow-lg shadow-[var(--color-accent)]/5"
                      : isCompleted
                      ? "bg-[var(--color-surface-2)]/60 border-[var(--color-border)] hover:border-[var(--color-accent)]/40 cursor-pointer"
                      : "bg-[var(--color-surface)]/40 border-[var(--color-border)]/50 opacity-60"
                  }`}
                  onClick={() => {
                    if (isCompleted && s.data) {
                      setExpandedStep(isExpanded ? null : s.node);
                    }
                  }}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      {/* Node Status Icon */}
                      <div
                        className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 border ${
                          isRunning
                            ? "bg-[var(--color-accent)]/20 border-[var(--color-accent)] text-[var(--color-accent)]"
                            : isCompleted
                            ? "bg-[var(--color-green-dim)] border-[var(--color-green)] text-[var(--color-green)]"
                            : "bg-[var(--color-surface-3)] border-[var(--color-border-2)] text-[var(--color-text-dim)]"
                        }`}
                      >
                        {isRunning ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : isCompleted ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          NODE_ICONS[s.node] ?? <span className="font-mono text-xs">{idx + 1}</span>
                        )}
                      </div>

                      {/* Node Title & Description */}
                      <div>
                        <div className="flex items-center gap-2">
                          <h3
                            className={`text-sm font-semibold ${
                              isRunning
                                ? "text-[var(--color-accent)]"
                                : isCompleted
                                ? "text-[var(--color-text)]"
                                : "text-[var(--color-text-muted)]"
                            }`}
                          >
                            {s.name}
                          </h3>
                          {isRunning && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-[var(--color-accent)]/20 text-[var(--color-accent)] font-semibold border border-[var(--color-accent)]/30">
                              Active Node
                            </span>
                          )}
                          {isCompleted && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-[var(--color-green-dim)] text-[var(--color-green)] font-semibold border border-[var(--color-green)]/30">
                              Done
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                          {s.description}
                        </p>
                      </div>
                    </div>

                    {/* Step index badge & expansion hint */}
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="font-mono text-[11px] text-[var(--color-text-dim)]">
                        Step {s.step}/7
                      </span>
                      {isCompleted && s.data && (
                        <span className="text-[var(--color-text-dim)]">
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Summary / Result snippet if completed */}
                  {isCompleted && s.summary && (
                    <div className="mt-2.5 ml-10 p-2 rounded bg-[var(--color-surface-1)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-accent)]">
                      <span className="text-[var(--color-text-dim)]">Output: </span>
                      {s.summary}
                    </div>
                  )}

                  {/* Expandable data inspect drawer */}
                  {isExpanded && s.data && (
                    <div className="mt-2 ml-10 p-3 rounded-lg bg-[var(--color-base)] border border-[var(--color-border)] text-[11px] font-mono text-[var(--color-text-muted)] overflow-x-auto max-h-48">
                      <div className="text-[10px] text-[var(--color-text-dim)] mb-1 font-semibold uppercase tracking-wider">
                        Raw Agent Output Payload:
                      </div>
                      <pre className="whitespace-pre-wrap">{JSON.stringify(s.data, null, 2)}</pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

          {/* Collapsible live telemetry terminal log */}
          <div className="mt-4 border border-[var(--color-border)] rounded-lg overflow-hidden bg-[var(--color-base)]">
            <button
              onClick={() => setShowLogs(!showLogs)}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-[var(--color-surface-2)] text-xs font-mono text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors border-b border-[var(--color-border)] cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-[var(--color-accent)]" />
                <span>Agent Execution Terminal Log ({logs.length} entries)</span>
              </span>
              {showLogs ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showLogs && (
              <div className="p-3 max-h-36 overflow-y-auto font-mono text-[11px] text-[var(--color-text-muted)] space-y-1 select-text">
                {logs.map((log, i) => (
                  <div key={i} className="leading-relaxed">
                    <span className="text-[var(--color-text-dim)]">&gt; </span>
                    <span
                      className={
                        log.includes("ERROR")
                          ? "text-[var(--color-red)] font-semibold"
                          : log.includes("Complete") || log.includes("Finished")
                          ? "text-[var(--color-success)] font-semibold"
                          : log.includes("WebSocket") || log.includes("SSE") || log.includes("Completed")
                          ? "text-[var(--color-text)]"
                          : "text-[var(--color-text-muted)]"
                      }
                    >
                      {log}
                    </span>
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-[var(--color-border)] px-6 py-4 bg-[var(--color-surface-2)] flex items-center justify-between">
          <div className="text-xs text-[var(--color-text-muted)]">
            {finalAlert && (
              <span className="flex items-center gap-3">
                <span>
                  Risk Score:{" "}
                  <strong className="text-[var(--color-accent)]">
                    {finalAlert.risk_score ?? "—"}/100
                  </strong>
                </span>
                <span>•</span>
                <span>
                  Priority:{" "}
                  <strong className="capitalize text-[var(--color-text)]">
                    {finalAlert.priority ?? "—"}
                  </strong>
                </span>
                <span>•</span>
                <span>
                  MITRE Techniques:{" "}
                  <strong className="text-[var(--color-text)]">
                    {finalAlert.mitre_mappings?.length ?? 0}
                  </strong>
                </span>
                <span>•</span>
                <span title="Engine that produced the risk score">
                  Assessed by:{" "}
                  <strong className="text-[var(--color-text)]">{engineLabel(finalAlert.engines?.risk)}</strong>
                </span>
                {finalAlert.unavailable_feeds && finalAlert.unavailable_feeds.length > 0 && (
                  <>
                    <span>•</span>
                    <span className="text-[#F59E0B]" title="These threat-intel feeds returned no verdict for this run">
                      No verdict from: {finalAlert.unavailable_feeds.join(", ")}
                    </span>
                  </>
                )}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            {isFinished && (
              <button
                onClick={() => void downloadPdf("full")}
                disabled={downloadingPdf}
                className="button-secondary text-xs flex items-center gap-1.5 cursor-pointer"
                title="Download full publication-ready investigation PDF report"
              >
                {downloadingPdf ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                <span>{downloadingPdf ? "Generating..." : "Download PDF Report"}</span>
              </button>
            )}
            <button
              onClick={onClose}
              className={isFinished ? "button-primary cursor-pointer" : "button-secondary cursor-pointer"}
            >
              {isFinished ? "Review Investigation Record" : "Close Window"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
