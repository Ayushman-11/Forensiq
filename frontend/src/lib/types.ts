export type FeedStatus = "ok" | "not_configured" | "error";
export type Enrichment = { ioc: string; ioc_type?: string; reputation?: string; threat_score?: number; source?: string; status?: FeedStatus };
export type Engines = { risk?: string; recommendation?: string };
export type TimelineEvent = { timestamp?: string; event_type?: string; description?: string; source?: string };
export type Correlation = { alert_id: string; title?: string; severity?: string; status?: string; matches?: { type?: string; value?: string }[] };
export type AlertRecord = {
  _id: string; title: string; severity: string; status: string; host?: string; user?: string; rule_name?: string; raw_alert_data?: Record<string, unknown>;
  alert_type?: string; created_at: string; ai_confidence?: number; risk_score?: number; priority?: string;
  recommendation?: string; enrichments?: Enrichment[]; extracted_iocs?: string[]; context?: Record<string, unknown>;
  mitre_tactic?: string; mitre_technique?: string; mitre_mappings?: { technique?: string; tactic?: string; name?: string }[];
  timeline?: TimelineEvent[]; correlations?: Correlation[]; evidence?: Record<string, number>; raw_event?: Record<string, unknown>;
  process_name?: string; command_line?: string; parent_process?: string; event_code?: string | number;
  source_ip?: string; dest_ip?: string; dest_port?: string | number; protocol?: string;
  registry_key?: string; registry_details?: string; dns_query?: string; hashes?: string;
  engines?: Engines; unavailable_feeds?: string[];
  incident_id?: string;
  detected_at?: string; acknowledged_at?: string; resolved_at?: string; resolved_by?: string;
  assignee_id?: string; assignee_email?: string; verdict?: string; disposition?: string; disposition_note?: string;
  sla?: { ack_due: string; resolve_due: string; ack_breached: boolean; resolve_breached: boolean } | null;
  risk_assessment?: { risk_score?: number; priority?: string; confidence_score?: number; reasoning?: string; blast_radius?: string; engine?: string };
};
export type InvestigationJob = { _id: string; status: string; created_at?: string; completed_at?: string; recommendation?: string; risk_assessment?: { risk_score?: number; priority?: string; confidence_score?: number } };

/** Why a feed result carries no verdict, or null when it is a real verdict. */
export function noVerdictLabel(e: Enrichment): string | null {
  if (e.status === "not_configured") return "Feed not configured";
  if (e.status === "error") return "Feed error";
  // Results stored before 2026-10-28 came from a simulation layer.
  if (/\((mock|error fallback)\)/i.test(e.source ?? "")) return "Simulated (ignore)";
  return null;
}

/** Human label for the engine that produced a result. Never claim an LLM ran when it did not. */
export function engineLabel(engine?: string): string {
  if (!engine || engine === "unknown") return "Unknown engine";
  if (engine === "deterministic_fallback") return "Rules engine";
  if (engine === "grok_llm") return "LLM (xAI Grok)";
  if (engine.startsWith("llm:")) return `LLM (${engine.slice(4)})`;
  return engine;
}

export type StepStatus = "pending" | "running" | "completed" | "failed";

export type PipelineStep = {
  step: number;
  node: string;
  name: string;
  description: string;
  status: StepStatus;
  summary?: string;
  data?: Record<string, unknown>;
};
