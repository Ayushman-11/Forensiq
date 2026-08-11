"""
Pytest Test Fixtures for Async FastAPI Backend Testing.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.infrastructure.siem.splunk import SplunkClient


@pytest_asyncio.fixture
async def client():
    """Async TestClient for FastAPI routes."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.fixture
def mock_splunk_auth_response():
    """Mock Splunk login JSON response."""
    return {"sessionKey": "mock_session_key_12345"}


@pytest.fixture
def mock_splunk_search_results():
    """Mock Splunk search result rows."""
    return [
        {
            "_time": "2026-08-06T14:00:00Z",
            "EventCode": "1",
            "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
            "host": "AYUSH-PC",
            "user": "AYUSH\\ayush",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentImage": "C:\\Windows\\System32\\powershell.exe",
        }
    ]
