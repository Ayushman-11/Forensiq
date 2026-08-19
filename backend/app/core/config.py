"""
Core Application Configuration Module.
Enforces type safety and environment variable loading using Pydantic Settings v2.
"""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FORENSIQ_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Configuration
    ENV: str = Field(default="development", description="Application runtime environment")
    DEBUG: bool = Field(default=True, description="Enable debug mode and verbose logs")
    SECRET_KEY: str = Field(
        default="default-development-secret-key-must-change-in-prod-min-32-chars",
        description="JWT signature secret key",
    )
    ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60 * 24, description="Access token TTL in minutes")
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60 * 24 * 7, description="Refresh token TTL in minutes (7 days)"
    )

    # Splunk Provider Configuration
    SPLUNK_URL: str = Field(default="https://localhost:8089", description="Splunk REST Management API URL")
    SPLUNK_USERNAME: str = Field(default="admin", description="Splunk REST API username")
    SPLUNK_PASSWORD: str = Field(default="ChangedPassword123!", description="Splunk REST API password")
    SPLUNK_VERIFY_SSL: bool = Field(default=False, description="Verify SSL certificates for Splunk API")
    SPLUNK_DEFAULT_INDEX: str = Field(default="main", description="Default Splunk index to search")

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

settings = Settings()
