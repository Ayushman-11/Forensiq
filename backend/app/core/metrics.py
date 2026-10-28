"""
Forensiq Prometheus Metrics Registry.

All application-level metrics are defined here as module-level singletons.
Import the objects you need; do not create metrics in other modules.

Metrics exposed at GET /metrics (via prometheus-fastapi-instrumentator).

Naming convention:  forensiq_<subsystem>_<name>_<unit>
"""

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Ingestion pipeline
# ---------------------------------------------------------------------------

INGEST_EVENTS_TOTAL = Counter(
    "forensiq_ingest_events_total",
    "Total raw events fetched from the SIEM across all ingestion cycles.",
)

INGEST_ALERTS_NEW_TOTAL = Counter(
    "forensiq_ingest_alerts_new_total",
    "Total new (de-duplicated) alerts inserted into MongoDB.",
)

INGEST_ALERTS_SEEN_TOTAL = Counter(
    "forensiq_ingest_alerts_seen_total",
    "Total alerts that were already known and skipped.",
)

INGEST_SUPPRESSED_TOTAL = Counter(
    "forensiq_ingest_suppressed_total",
    "Total events suppressed by the noise policy.",
    labelnames=["reason"],
)

INGEST_RULE_ERRORS_TOTAL = Counter(
    "forensiq_ingest_rule_errors_total",
    "Total detection-rule evaluation errors.",
)

INGEST_CYCLE_ERRORS_TOTAL = Counter(
    "forensiq_ingest_cycle_errors_total",
    "Total ingestion cycles that ended in error.",
)

INGEST_LAG_SECONDS = Gauge(
    "forensiq_ingest_lag_seconds",
    "Seconds between the newest ingested event timestamp and now (staleness).",
)

INGEST_CYCLE_DURATION_SECONDS = Histogram(
    "forensiq_ingest_cycle_duration_seconds",
    "Wall-clock time for a complete ingestion cycle.",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

# ---------------------------------------------------------------------------
# Threat-intelligence enrichment
# ---------------------------------------------------------------------------

TI_LOOKUPS_TOTAL = Counter(
    "forensiq_ti_lookups_total",
    "Total threat-intelligence lookups performed.",
    labelnames=["source"],   # e.g. virustotal, abuseipdb
)

TI_ERRORS_TOTAL = Counter(
    "forensiq_ti_errors_total",
    "Total failed threat-intelligence lookups.",
    labelnames=["source"],
)

TI_CACHE_HITS_TOTAL = Counter(
    "forensiq_ti_cache_hits_total",
    "Total IOC lookups served from the MongoDB cache.",
)

# ---------------------------------------------------------------------------
# AI investigation pipeline
# ---------------------------------------------------------------------------

INVESTIGATION_STARTED_TOTAL = Counter(
    "forensiq_investigation_started_total",
    "Total AI investigation runs started.",
)

INVESTIGATION_COMPLETED_TOTAL = Counter(
    "forensiq_investigation_completed_total",
    "Total AI investigation runs that completed successfully.",
)

INVESTIGATION_FAILED_TOTAL = Counter(
    "forensiq_investigation_failed_total",
    "Total AI investigation runs that failed.",
)

INVESTIGATION_DURATION_SECONDS = Histogram(
    "forensiq_investigation_duration_seconds",
    "End-to-end duration of a single AI investigation run.",
    buckets=[1, 5, 15, 30, 60, 120, 300, 600],
)

INVESTIGATION_QUEUE_DEPTH = Gauge(
    "forensiq_investigation_queue_depth",
    "Number of auto-investigation tasks currently running (bounded by semaphore).",
)

# ---------------------------------------------------------------------------
# LLM / model calls
# ---------------------------------------------------------------------------

LLM_REQUESTS_TOTAL = Counter(
    "forensiq_llm_requests_total",
    "Total LLM API calls made.",
    labelnames=["model"],
)

LLM_ERRORS_TOTAL = Counter(
    "forensiq_llm_errors_total",
    "Total LLM API calls that returned an error.",
    labelnames=["model"],
)

LLM_LATENCY_SECONDS = Histogram(
    "forensiq_llm_latency_seconds",
    "Latency of individual LLM API calls.",
    labelnames=["model"],
    buckets=[0.5, 1, 2, 5, 10, 30, 60],
)

LLM_TOKENS_TOTAL = Counter(
    "forensiq_llm_tokens_total",
    "Total tokens consumed (prompt + completion combined).",
    labelnames=["model", "direction"],  # direction: prompt | completion
)

# ---------------------------------------------------------------------------
# Poller / lease
# ---------------------------------------------------------------------------

POLLER_LEASE_LOST_TOTAL = Counter(
    "forensiq_poller_lease_lost_total",
    "Total times the poller lost its MongoDB lease.",
)

POLLER_CYCLES_TOTAL = Counter(
    "forensiq_poller_cycles_total",
    "Total completed poller cycles (whether alerts were found or not).",
)

POLLER_IS_LEADER = Gauge(
    "forensiq_poller_is_leader",
    "1 if this process currently holds the poller lease, 0 otherwise.",
)

# ---------------------------------------------------------------------------
# SLA / alert queue health
# ---------------------------------------------------------------------------

SLA_BREACHES_TOTAL = Counter(
    "forensiq_sla_breaches_total",
    "Total SLA breach events emitted.",
    labelnames=["severity"],
)

ALERTS_OPEN_TOTAL = Gauge(
    "forensiq_alerts_open_total",
    "Current count of open (New + Investigating) alerts.",
)

ALERTS_BACKLOG_AGE_SECONDS = Histogram(
    "forensiq_alerts_backlog_age_seconds",
    "Age in seconds of open alerts at the time they are read from the backlog.",
    buckets=[60, 300, 900, 1800, 3600, 7200, 14400, 86400],
)
