"""
FastAPI Route Dependencies.
Provides Dependency Injection for SIEM Clients, Database Sessions, and Services.
"""

from typing import AsyncGenerator
from app.infrastructure.siem.splunk import SplunkClient
from app.infrastructure.siem.base import SIEMProvider


async def get_siem_client() -> AsyncGenerator[SIEMProvider, None]:
    """Dependency Provider for SIEM Client (SplunkClient). Ensures client is closed after request."""
    client = SplunkClient()
    try:
        yield client
    finally:
        await client.close()
