"""
Core Application Configuration Module.
Enforces type safety and environment variable loading using Pydantic Settings v2.
Integrates file-based secrets mounts (Vault/K8s/Docker secrets) and key rotation.
"""

from pathlib import Path
from typing import List, Optional
import os
import urllib.parse
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.core.secrets import load_secret_from_file_or_env
import logging

_cfg_logger = logging.getLogger("forensiq.config")

DEFAULT_SECRET_KEY = "default-development-secret-key-must-change-in-prod-min-32-chars"
DEFAULT_SPLUNK_PASSWORD = "ChangedPassword123!"

_NON_PRODUCTION_ENVS = frozenset({"development", "dev", "test", "testing", "local"})
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FORENSIQ_",
        env_file=(".env", str(_ENV_FILE)),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # General Configuration
    ENV: str = Field(default="development", description="Application runtime environment")
    DEBUG: bool = Field(default=False, description="Enable debug mode and verbose logs")
    SECRETS_DIR: Optional[str] = Field(
        default=None,
        description="Path to directory containing mounted secrets (e.g. /run/secrets or Vault mount)",
    )

    # Secret keys with rotation support
    SECRET_KEY: str = Field(
        default=DEFAULT_SECRET_KEY,
        description="Active JWT signature secret key",
    )
    PREVIOUS_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Previous JWT secret key accepted for 1 TTL during graceful key rotation",
    )

    ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, description="Access token TTL in minutes")
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60 * 24 * 7, description="Refresh token TTL in minutes (7 days)"
    )

    # Request body size limit
    MAX_REQUEST_BODY_BYTES: int = Field(
        default=2 * 1024 * 1024, # 2 MB default limit
        description="Maximum allowed request payload size in bytes",
    )

    # Splunk Provider Configuration
    SPLUNK_URL: str = Field(default="https://localhost:8089", description="Splunk REST Management API URL")
    SPLUNK_USERNAME: str = Field(default="admin", description="Splunk REST API username")
    SPLUNK_PASSWORD: str = Field(default=DEFAULT_SPLUNK_PASSWORD, description="Splunk REST API password")
    SPLUNK_VERIFY_SSL: bool = Field(
        default=True,
        description="Verify TLS certificates for Splunk REST API. Only disable in dev with FORENSIQ_SPLUNK_VERIFY_SSL=false.",
    )
    SPLUNK_CA_BUNDLE: Optional[str] = Field(
        default=None,
        description="Path to a custom CA bundle (PEM file) for Splunk TLS verification. Leave empty to use system CAs.",
    )
    SPLUNK_DEFAULT_INDEX: str = Field(default="main", description="Default Splunk index to search")
    SPLUNK_DETECTION_INDEX: str = Field(default="windows", description="Index containing detection telemetry")
    SPLUNK_ALLOWED_INDEXES: List[str] = Field(
        default=["windows"], description="Indexes users may query through /search"
    )
    SEARCH_MAX_RANGE_DAYS: int = Field(default=30, description="Maximum lookback for /search queries")

    # Login throttling
    LOGIN_MAX_FAILURES: int = Field(default=5, description="Failed logins per email+IP before lockout")
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, description="Lockout duration in minutes")

    # API rate limiting (per-user sliding window)
    RATE_LIMIT_SEARCH_MAX: int = Field(default=30, description="Max /search requests per window")
    RATE_LIMIT_SEARCH_WINDOW: int = Field(default=60, description="/search rate limit window in seconds")
    RATE_LIMIT_INVESTIGATE_MAX: int = Field(default=10, description="Max /investigate requests per window")
    RATE_LIMIT_INVESTIGATE_WINDOW: int = Field(default=60, description="/investigate rate limit window in seconds")
    RATE_LIMIT_REPORT_MAX: int = Field(default=10, description="Max report/PDF requests per window")
    RATE_LIMIT_REPORT_WINDOW: int = Field(default=60, description="Report rate limit window in seconds")
    RATE_LIMIT_BULK_MAX: int = Field(default=15, description="Max bulk-action requests per window")
    RATE_LIMIT_BULK_WINDOW: int = Field(default=60, description="Bulk-action rate limit window in seconds")

    # Trusted hosts (production)
    TRUSTED_HOSTS: List[str] = Field(
        default=["*"],
        description="Allowed Host header values. Set to your domain(s) in production.",
    )

    # Database Configuration
    MONGO_URI: str = Field(
        default="mongodb://localhost:27017",
        description="MongoDB Connection URL",
    )
    MONGO_DB_NAME: str = Field(
        default="forensiq",
        description="MongoDB Database Name",
    )

    # Redis Configuration
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis Connection URL for Caching and Celery",
    )

    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed CORS origins",
    )

    # Threat Intel Configuration
    VT_API_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("FORENSIQ_VT_API_KEY", "VT_API_KEY"),
        description="VirusTotal API Key (v3)"
    )
    ABUSEIPDB_API_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("FORENSIQ_ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY"),
        description="AbuseIPDB API Key (v2)"
    )
    IOC_CACHE_TTL_HOURS: int = Field(
        default=24,
        description="Time to live in hours for cached IOC enrichments in MongoDB"
    )
    VT_MALICIOUS_MIN_ENGINES: int = Field(
        default=3,
        description="VirusTotal engines that must flag an IOC before it is rated malicious; fewer flags rate it suspicious"
    )
    ABUSEIPDB_MALICIOUS_MIN_SCORE: int = Field(
        default=75, description="AbuseIPDB confidence score at or above which an IP is rated malicious"
    )
    ABUSEIPDB_SUSPICIOUS_MIN_SCORE: int = Field(
        default=25, description="AbuseIPDB confidence score at or above which an IP is rated suspicious"
    )

    # Ingestion pipeline
    INGEST_OVERLAP_SECONDS: int = Field(default=120, description="Re-query overlap to catch late-indexed events")
    INGEST_MAX_PAGES: int = Field(default=20, description="Max result pages fetched per ingestion cycle")
    INGEST_PAGE_SIZE: int = Field(default=500, description="Rows per Splunk result page")
    INGEST_INITIAL_LOOKBACK_HOURS: int = Field(default=720, description="First-run lookback window in hours")
    INGEST_DEDUP_BUCKET_SECONDS: int = Field(default=300, description="Time bucket for collapsing repeated detections")
    BRUTE_FORCE_THRESHOLD: int = Field(default=5, description="Failed logons per bucket and source that raise an alert")
    NOISE_CONFIG_PATH: str = Field(default="config/noise.yaml", description="Noise suppression policy file")
    INVESTIGATION_CONCURRENCY: int = Field(default=3, description="Max concurrent auto-investigations")
    POLLER_LEASE_TTL_SECONDS: int = Field(default=90, description="Single-poller lease time to live")
    POLLER_INTERVAL_SECONDS: int = Field(default=30, description="Seconds between SIEM ingestion cycles")
    INCIDENT_WINDOW_HOURS: int = Field(default=6, description="Alerts sharing a link key within this gap join one incident")
    SLA_SWEEP_INTERVAL_SECONDS: int = Field(default=60, description="Seconds between SLA breach / escalation sweeps")

    # External ticketing (case management). Each system is optional; unset means "not configured".
    JIRA_BASE_URL: str = Field(default="", description="e.g. https://acme.atlassian.net")
    JIRA_EMAIL: str = Field(default="", description="Jira account email used with the API token")
    JIRA_API_TOKEN: str = Field(default="", description="Jira API token")
    JIRA_PROJECT_KEY: str = Field(default="", description="Project new tickets are created in")
    JIRA_ISSUE_TYPE: str = Field(default="Task", description="Issue type for created tickets")
    SERVICENOW_INSTANCE_URL: str = Field(default="", description="e.g. https://acme.service-now.com")
    SERVICENOW_USER: str = Field(default="", description="ServiceNow integration user")
    SERVICENOW_PASSWORD: str = Field(default="", description="ServiceNow integration password")
    TICKET_SYNC_INTERVAL_SECONDS: int = Field(default=300, description="How often linked tickets are polled for status")

    # Response actions (EDR isolate, IdP disable user, firewall block). Dry runs always work;
    # live execution stays off until an operator turns it on.
    RESPONSE_LIVE_EXECUTION_ENABLED: bool = Field(default=False, description="Allow approved response actions to change the target system")
    RESPONSE_REQUEST_TTL_HOURS: int = Field(default=24, description="A request nobody approves within this time expires")
    RESPONSE_APPROVAL_TTL_MINUTES: int = Field(default=60, description="An approval must be used within this time")
    RESPONSE_MAX_LIVE_PER_HOUR: int = Field(default=10, description="Circuit breaker: live executions per tenant per hour")
    RESPONSE_PROTECTED_TARGETS: str = Field(default="", description="Comma-separated hosts, accounts or IPs that may never be actioned (domain controllers, break-glass accounts)")
    CROWDSTRIKE_BASE_URL: str = Field(default="https://api.crowdstrike.com", description="CrowdStrike Falcon API base URL for your cloud")
    CROWDSTRIKE_CLIENT_ID: str = Field(default="", description="Falcon API client id (scope: Hosts write)")
    CROWDSTRIKE_CLIENT_SECRET: str = Field(default="", description="Falcon API client secret")
    OKTA_BASE_URL: str = Field(default="", description="e.g. https://acme.okta.com")
    OKTA_API_TOKEN: str = Field(default="", description="Okta API token (SSWS) allowed to suspend users")
    FIREWALL_WEBHOOK_URL: str = Field(default="", description="HTTPS endpoint of the firewall automation gateway that applies block/unblock")
    FIREWALL_WEBHOOK_TOKEN: str = Field(default="", description="Bearer token sent to the firewall gateway")

    # Data Durability & Governance (Retention in days)
    AUDIT_RETENTION_DAYS: int = Field(default=365, description="Retention in days for audit logs")
    INVESTIGATION_JOB_RETENTION_DAYS: int = Field(default=90, description="Retention in days for completed investigation jobs")
    ALERT_NOTE_RETENTION_DAYS: int = Field(default=365, description="Retention in days for alert notes")
    RAW_EVENTS_RETENTION_DAYS: int = Field(default=90, description="Retention in days for raw events")
    RAW_EVENTS_REDACT_PII: bool = Field(default=False, description="Redact personal data in raw events on ingestion")

    # Investigation Queue & Worker Configuration
    INVESTIGATION_JOB_LEASE_SECONDS: int = Field(default=300, description="Worker lease duration before a running job is considered stuck")
    INVESTIGATION_MAX_RETRIES: int = Field(default=3, description="Maximum retry attempts for failed investigation jobs")
    INVESTIGATION_WORKER_POLL_INTERVAL_SECONDS: float = Field(default=2.0, description="Polling interval for background investigation worker")

    # Grok / xAI LLM Configuration
    XAI_API_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("FORENSIQ_XAI_API_KEY", "XAI_API_KEY"),
        description="xAI Grok API Key",
    )
    XAI_BASE_URL: str = Field(
        default="https://api.x.ai/v1",
        description="xAI API Base URL",
    )
    XAI_MODEL: str = Field(
        default="grok-beta",
        description="xAI Grok Model name (e.g. grok-beta, grok-2-latest)",
    )

    # AI Investigation Governance & Cost Controls (Section 2.3)
    LLM_PROMPT_VERSION: str = Field(default="v1.2.0", description="Semantic version of active LLM investigation prompts")
    LLM_DAILY_TENANT_CAP_USD: float = Field(default=25.0, description="Daily spending limit in USD per tenant for LLM investigation queries")
    LLM_PRICE_PER_1K_PROMPT_TOKENS: float = Field(default=0.002, description="Estimated USD cost per 1,000 prompt tokens")
    LLM_PRICE_PER_1K_COMPLETION_TOKENS: float = Field(default=0.010, description="Estimated USD cost per 1,000 completion tokens")
    LLM_CIRCUIT_BREAKER_MAX_FAILURES: int = Field(default=5, description="Consecutive LLM failures before circuit breaker trips open")
    LLM_CIRCUIT_BREAKER_RESET_SECONDS: int = Field(default=60, description="Cooldown seconds before tripped circuit breaker resets to half-open")
    LLM_MIN_EVAL_PRECISION: float = Field(default=0.80, description="Minimum benchmark precision target before release regression failure")
    LLM_MIN_EVAL_RECALL: float = Field(default=0.80, description="Minimum benchmark recall target before release regression failure")

    @model_validator(mode="after")
    def _load_mounted_secrets_and_validate(self) -> "Settings":
        """
        1. Checks mounted secrets directory for external secrets override (e.g. Vault / K8s).
        2. Validates security constraints for production environments.
        """
        # Load secrets from SECRETS_DIR if configured
        if self.SECRETS_DIR:
            self.SECRET_KEY = load_secret_from_file_or_env("secret_key", self.SECRET_KEY, self.SECRETS_DIR)
            self.PREVIOUS_SECRET_KEY = load_secret_from_file_or_env("previous_secret_key", self.PREVIOUS_SECRET_KEY or "", self.SECRETS_DIR) or None
            self.SPLUNK_PASSWORD = load_secret_from_file_or_env("splunk_password", self.SPLUNK_PASSWORD, self.SECRETS_DIR)
            self.XAI_API_KEY = load_secret_from_file_or_env("xai_api_key", self.XAI_API_KEY, self.SECRETS_DIR)
            self.VT_API_KEY = load_secret_from_file_or_env("vt_api_key", self.VT_API_KEY, self.SECRETS_DIR)
            self.ABUSEIPDB_API_KEY = load_secret_from_file_or_env("abuseipdb_api_key", self.ABUSEIPDB_API_KEY, self.SECRETS_DIR)

        # Warn if Threat Intel or LLM keys are absent in any environment
        if not self.XAI_API_KEY:
            _cfg_logger.warning("config_warning_missing_llm_key: FORENSIQ_XAI_API_KEY is not configured; deterministic fallback will be used.")
        if not self.VT_API_KEY and not self.ABUSEIPDB_API_KEY:
            _cfg_logger.warning("config_warning_missing_threat_intel_keys: Neither VT_API_KEY nor ABUSEIPDB_API_KEY are configured; IOC enrichment will be disabled.")

        if self.ENV.strip().lower() in _NON_PRODUCTION_ENVS:
            return self

        problems = []
        # Production secret checks
        if self.SECRET_KEY == DEFAULT_SECRET_KEY:
            problems.append("FORENSIQ_SECRET_KEY must not be the insecure default development key")
        elif len(self.SECRET_KEY) < 32:
            problems.append("FORENSIQ_SECRET_KEY must be at least 32 characters")

        if self.SPLUNK_PASSWORD == DEFAULT_SPLUNK_PASSWORD:
            problems.append("FORENSIQ_SPLUNK_PASSWORD must not be the default")
        if not self.SPLUNK_PASSWORD:
            problems.append("FORENSIQ_SPLUNK_PASSWORD must not be empty")

        if self.DEBUG:
            problems.append("FORENSIQ_DEBUG must be false in production")

        if not self.SPLUNK_VERIFY_SSL:
            problems.append(
                "FORENSIQ_SPLUNK_VERIFY_SSL must be true in production "
                "(set FORENSIQ_SPLUNK_CA_BUNDLE for custom CAs)"
            )

        if "*" in self.CORS_ORIGINS:
            problems.append("FORENSIQ_CORS_ORIGINS must not contain '*' wildcard in production")

        if self.TRUSTED_HOSTS == ["*"]:
            problems.append(
                "FORENSIQ_TRUSTED_HOSTS must be set to your domain(s) in production, not '*'"
            )

        # Production MongoDB authentication and network checks
        parsed_mongo = urllib.parse.urlparse(self.MONGO_URI)
        host = parsed_mongo.hostname or ""
        is_local_unauth = (
            host in ("localhost", "127.0.0.1", "::1")
            and not parsed_mongo.username
        )
        if is_local_unauth:
            problems.append(
                "FORENSIQ_MONGO_URI in production must not point to an unauthenticated localhost instance. "
                "Configure replica set with credentials and TLS."
            )

        if problems:
            raise ValueError("Refusing to start in production: " + "; ".join(problems))

        return self


settings = Settings()
