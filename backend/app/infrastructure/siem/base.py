"""
SIEM Provider Abstract Interface Protocol.
Decouples Forensiq services and AI agents from specific SIEM implementations.
"""

from typing import Protocol

from app.schemas.normalized_event import NormalizedAlert, NormalizedEvent


class SIEMProvider(Protocol):
    """
    Abstract interface protocol for all telemetry and SIEM providers (Splunk, Elastic, Sentinel, QRadar, Wazuh).
    """

    async def authenticate(self) -> bool:
        """Authenticates with the SIEM API."""
        ...

    async def search(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        limit: int = 100,
    ) -> list[NormalizedEvent]:
        """Executes a search query and returns normalized security events."""
        ...

    async def list_alerts(self, limit: int = 50) -> list[NormalizedAlert]:
        """Lists recent triggered alerts from the SIEM."""
        ...

    async def list_indexes(self) -> list[str]:
        """Lists all available indexes in the SIEM."""
        ...
