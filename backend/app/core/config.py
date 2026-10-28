"""
Core Application Configuration Module.
Enforces type safety and environment variable loading using Pydantic Settings v2.
Integrates file-based secrets mounts (Vault/K8s/Docker secrets) and key rotation.
"""

from pathlib import Path
from typing import List, Optional
import os
import urllib.parse
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.core.secrets import load_secret_from_file_or_env
from app.core.logging import logger

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
        description="VirusTotal API Key (v3)"
    )
    ABUSEIPDB_API_KEY: str = Field(
        default="",
        description="AbuseIPDB API Key (v2)"
    )
    IOC_CACHE_TTL_HOURS: int = Field(
        default=24,
        description="Time to live in hours for cached IOC enrichments in MongoDB"
    )

    # Ingestion pipeline
    INGEST_OVERLAP_SECONDS: int = Field(default=120, description="Re-query overlap to catch late-indexed events")
    INGEST_MAX_PAGES: int = Field(default=20, description="Max result pages fetched per ingestion cycle")
    INGEST_PAGE_SIZE: int = Field(default=500, description="Rows per Splunk result page")
    INGEST_INITIAL_LOOKBACK_HOURS: int = Field(default=168, description="First-run lookback window in hours")
    INGEST_DEDUP_BUCKET_SECONDS: int = Field(default=300, description="Time bucket for collapsing repeated detections")
    BRUTE_FORCE_THRESHOLD: int = Field(default=5, description="Failed logons per bucket and source that raise an alert")
    NOISE_CONFIG_PATH: str = Field(default="config/noise.yaml", description="Noise suppression policy file")
    INVESTIGATION_CONCURRENCY: int = Field(default=3, description="Max concurrent auto-investigations")
    POLLER_LEASE_TTL_SECONDS: int = Field(default=90, description="Single-poller lease time to live")

    # Grok / xAI LLM Configuration
    XAI_API_KEY: str = Field(
        default="",
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
            logger.warning("config_warning_missing_llm_key", detail="FORENSIQ_XAI_API_KEY is not configured; AI agent investigations will fail.")
        if not self.VT_API_KEY and not self.ABUSEIPDB_API_KEY:
            logger.warning("config_warning_missing_threat_intel_keys", detail="Neither VT_API_KEY nor ABUSEIPDB_API_KEY are configured; IOC enrichment will be disabled.")

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
