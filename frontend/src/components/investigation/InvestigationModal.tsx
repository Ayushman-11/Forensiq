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
} from "lucide-react";
import { apiFetch } from "@/lib/api";
import type { AlertRecord, PipelineStep, StepStatus } from "@/lib/types";

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
    name: "AI Risk Assessment",
    description: "Scoring threat impact, confidence, and blast radius via Grok AI engine",
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

  const logsEndRef = useRef<HTMLDivElement | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  useEffect(() => {
    if (!isOpen) return;

    // Reset state for new investigation run
    setSteps(INITIAL_STEPS.map((s, idx) => ({ ...s, status: idx === 0 ? "running" : "pending" })));
    setCurrentStepIndex(0);
    setIsFinished(false);
    setStreamError(null);
    setFinalAlert(null);
    setLogs([`[${new Date().toLocaleTimeString()}] Initializing AI agent investigation pipeline for alert: ${alert.title}`]);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    async function startStream() {
      try {
        const response = await apiFetch(`/api/v1/alerts/${alert._id}/investigate/stream`, {
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

    void startStream();

    return () => {
      controller.abort();
    };
  }, [isOpen, alert._id, alert.title]);

  function handleStreamEvent(eventType: string, data: any) {
    const time = new Date().toLocaleTimeString();

    if (eventType === "init") {
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
      setIsFinished(true);
      const updated = data.alert as AlertRecord;
      setFinalAlert(updated);
      setLogs((prev) => [
        ...prev,
        `[${time}] Pipeline investigation complete! Risk Score: ${updated.risk_score ?? "N/A"}/100, AI Confidence: ${updated.ai_confidence ?? "N/A"}%.`,
      ]);
      onComplete(updated);
    } else if (eventType === "error") {
      setStreamError(data.error || "Investigation failed");
      setLogs((prev) => [...prev, `[${time}] Pipeline error: ${data.error}`]);
    }
  }

  if (!isOpen) return null;

  const completedCount = steps.filter((s) => s.status === "completed").length;
  const progressPercent = Math.min(100, Math.round((completedCount / steps.length) * 100));

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
              </div>
              <h2 className="text-base font-bold text-[var(--color-text)] truncate max-w-lg">
                {alert.title}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-surface-3)] transition-colors"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
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
                  Streaming live telemetry...
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
          {streamError && (
            <div className="p-4 rounded-lg bg-[var(--color-red)]/10 border border-[var(--color-red)]/30 text-[var(--color-red)] text-sm flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Pipeline Execution Warning</p>
                <p className="text-xs opacity-90 mt-1">{streamError}</p>
              </div>
            </div>
          )}

          {/* Stepper list */}
          <div className="space-y-2">
            {steps.map((s, idx) => {
              const isRunning = s.status === "running";
              const isCompleted = s.status === "completed";
              const isPending = s.status === "pending";

              return (
                <div
                  key={s.node}
                  className={`p-3.5 rounded-lg border transition-all ${
                    isRunning
                      ? "bg-[var(--color-surface-2)] border-[var(--color-accent)]/60 shadow-lg shadow-[var(--color-accent)]/5"
                      : isCompleted
                      ? "bg-[var(--color-surface-2)]/60 border-[var(--color-border)]"
                      : "bg-[var(--color-surface)]/40 border-[var(--color-border)]/50 opacity-60"
                  }`}
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

                    {/* Step index badge */}
                    <span className="font-mono text-[11px] text-[var(--color-text-dim)] shrink-0">
                      Step {s.step}/7
                    </span>
                  </div>

                  {/* Summary / Result snippet if completed */}
                  {isCompleted && s.summary && (
                    <div className="mt-2.5 ml-10 p-2 rounded bg-[var(--color-surface-1)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-accent)]">
                      <span className="text-[var(--color-text-dim)]">Output: </span>
                      {s.summary}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Collapsible live telemetry terminal log */}
          <div className="mt-4 border border-[var(--color-border)] rounded-lg overflow-hidden bg-[var(--color-base)]">
            <button
              onClick={() => setShowLogs(!showLogs)}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-[var(--color-surface-2)] text-xs font-mono text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors border-b border-[var(--color-border)]"
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
                          : log.includes("Active") || log.includes("Completed")
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
                    {finalAlert.priority ?? "medium"}
                  </strong>
                </span>
                <span>•</span>
                <span>
                  MITRE Techniques:{" "}
                  <strong className="text-[var(--color-text)]">
                    {finalAlert.mitre_mappings?.length ?? 0}
                  </strong>
                </span>
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className={isFinished ? "button-primary" : "button-secondary"}
            >
              {isFinished ? "Review Investigation Record" : "Close Window"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
