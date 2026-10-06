"""
Pytest Test Fixtures for Async FastAPI Backend Testing.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient
from app.main import app
from app.database.session import get_db
from app.infrastructure.siem.splunk import SplunkClient


@pytest_asyncio.fixture
async def client():
    """Async TestClient for FastAPI routes, isolated from the real MongoDB."""
    mock_db = AsyncMongoMockClient()["conftest_db"]

    async def _db():
        return mock_db

    app.dependency_overrides[get_db] = _db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_db, None)


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


import json
from pathlib import Path


@pytest.fixture(scope="session")
def splunk_rows():
    """Real Splunk rows (from the lab dump) keyed by EventCode string."""
    path = Path(__file__).parent / "fixtures" / "splunk_rows.json"
    return json.loads(path.read_text(encoding="utf-8"))
