"""
SIEM Provider Abstract Interface Protocol.
Decouples Forensiq services and AI agents from specific SIEM implementations.
"""

from typing import Protocol, List, Optional, Dict, Any
from datetime import datetime
from app.schemas.normalized_event import NormalizedEvent, NormalizedAlert


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
    ) -> List[NormalizedEvent]:
        """Executes a search query and returns normalized security events."""
        ...

    async def list_alerts(self, limit: int = 50) -> List[NormalizedAlert]:
        """Lists recent triggered alerts from the SIEM."""
        ...

    async def list_indexes(self) -> List[str]:
        """Lists all available indexes in the SIEM."""
        ...
