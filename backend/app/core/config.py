"""
Core Application Configuration Module.
Enforces type safety and environment variable loading using Pydantic Settings v2.
"""

from typing import List
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Named constant so the "insecure default" comparison isn't a fragile string
# duplicate between the field default and the production fail-fast check.
DEFAULT_SECRET_KEY = "default-development-secret-key-must-change-in-prod-min-32-chars"
DEFAULT_SPLUNK_PASSWORD = "ChangedPassword123!"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FORENSIQ_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Configuration
    ENV: str = Field(default="development", description="Application runtime environment")
    DEBUG: bool = Field(default=False, description="Enable debug mode and verbose logs")
    SECRET_KEY: str = Field(
        default=DEFAULT_SECRET_KEY,
        description="JWT signature secret key",
    )
    ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, description="Access token TTL in minutes")
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60 * 24 * 7, description="Refresh token TTL in minutes (7 days)"
    )

    # Splunk Provider Configuration
    SPLUNK_URL: str = Field(default="https://localhost:8089", description="Splunk REST Management API URL")
    SPLUNK_USERNAME: str = Field(default="admin", description="Splunk REST API username")
    SPLUNK_PASSWORD: str = Field(default=DEFAULT_SPLUNK_PASSWORD, description="Splunk REST API password")
    SPLUNK_VERIFY_SSL: bool = Field(default=False, description="Verify SSL certificates for Splunk API")
    SPLUNK_DEFAULT_INDEX: str = Field(default="main", description="Default Splunk index to search")
    SPLUNK_DETECTION_INDEX: str = Field(default="windows", description="Index containing detection telemetry")
    SPLUNK_ALLOWED_INDEXES: List[str] = Field(
        default=["windows"], description="Indexes users may query through /search"
    )
    SEARCH_MAX_RANGE_DAYS: int = Field(default=30, description="Maximum lookback for /search queries")

    # Login throttling
    LOGIN_MAX_FAILURES: int = Field(default=5, description="Failed logins per email+IP before lockout")
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, description="Lockout duration in minutes")

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
    def _reject_insecure_production_settings(self) -> "Settings":
        """Fail fast at startup if production runs with insecure defaults. Development/test are unaffected."""
        if self.ENV.lower() != "production":
            return self
        problems = []
        if self.SECRET_KEY == DEFAULT_SECRET_KEY:
            problems.append("FORENSIQ_SECRET_KEY must not be the insecure default development key")
        elif len(self.SECRET_KEY) < 32:
            problems.append("FORENSIQ_SECRET_KEY must be at least 32 characters")
        if self.SPLUNK_PASSWORD == DEFAULT_SPLUNK_PASSWORD:
            problems.append("FORENSIQ_SPLUNK_PASSWORD must not be the default")
        if self.DEBUG:
            problems.append("FORENSIQ_DEBUG must be false in production")
        if problems:
            raise ValueError("Refusing to start in production: " + "; ".join(problems))
        return self


settings = Settings()
