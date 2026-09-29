export type Enrichment = { ioc: string; ioc_type?: string; reputation?: string; threat_score?: number; source?: string };
export type TimelineEvent = { timestamp?: string; event_type?: string; description?: string; source?: string };
export type Correlation = { alert_id: string; title?: string; severity?: string; status?: string; matches?: { type?: string; value?: string }[] };
export type AlertRecord = {
  _id: string; title: string; severity: string; status: string; host?: string; user?: string; rule_name?: string; raw_alert_data?: Record<string, unknown>;
  alert_type?: string; created_at: string; ai_confidence?: number; risk_score?: number; priority?: string;
  recommendation?: string; enrichments?: Enrichment[]; extracted_iocs?: string[]; context?: Record<string, unknown>;
  mitre_tactic?: string; mitre_technique?: string; mitre_mappings?: { technique?: string; tactic?: string; name?: string }[];
  timeline?: TimelineEvent[]; correlations?: Correlation[]; evidence?: Record<string, number>; raw_event?: Record<string, unknown>;
};
export type InvestigationJob = { _id: string; status: string; created_at?: string; completed_at?: string; recommendation?: string; risk_assessment?: { risk_score?: number; priority?: string; confidence_score?: number } };
