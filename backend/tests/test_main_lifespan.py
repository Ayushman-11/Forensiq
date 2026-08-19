"""Tests for app startup / app-construction behavior:
- the sessions TTL index created in `lifespan`
- gating /docs, /redoc, /openapi.json behind settings.DEBUG

The real `lifespan` connects to a real MongoDB and starts the AlertPoller,
neither of which we want to exercise in unit tests. Instead we patch
`connect_to_mongo` to inject a mongomock client into `db_config.client` and
patch `AlertPoller.start` to a no-op, then drive the real `lifespan`
context manager directly to prove it creates the TTL index on `sessions`.
"""

import importlib
from unittest.mock import Mock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

import app.main as main_module
from app.main import lifespan, app
from app.core.config import settings
from app.database.session import db_config


@pytest.mark.asyncio
async def test_lifespan_creates_sessions_ttl_index():
    mock_client = AsyncMongoMockClient()

    async def fake_connect_to_mongo():
        db_config.client = mock_client

    with patch("app.main.connect_to_mongo", new=fake_connect_to_mongo), \
         patch("app.main.AlertPoller.start", new=Mock()):
        async with lifespan(app):
            indexes = await mock_client["forensiq"]["sessions"].index_information()
            assert "expires_at_1" in indexes
            assert indexes["expires_at_1"]["expireAfterSeconds"] == 0

    db_config.client = None


def test_docs_routes_disabled_when_debug_false():
    """/docs, /redoc, /openapi.json must be unregistered outside debug mode,
    since they sit outside api_router and are never covered by
    Depends(get_current_user)."""
    original_debug = settings.DEBUG
    try:
        settings.DEBUG = False
        importlib.reload(main_module)
        assert main_module.app.docs_url is None
        assert main_module.app.redoc_url is None
        assert main_module.app.openapi_url is None
    finally:
        settings.DEBUG = original_debug
        importlib.reload(main_module)


def test_docs_routes_enabled_when_debug_true():
    """Sanity check: local development keeps the docs routes available."""
    original_debug = settings.DEBUG
    try:
        settings.DEBUG = True
        importlib.reload(main_module)
        assert main_module.app.docs_url == "/docs"
        assert main_module.app.redoc_url == "/redoc"
        assert main_module.app.openapi_url == "/openapi.json"
    finally:
        settings.DEBUG = original_debug
        importlib.reload(main_module)
