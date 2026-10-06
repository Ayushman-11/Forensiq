import re
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from app.api.v1.endpoints import alerts as alerts_module
from app.core.errors import internal_error, new_request_id
from app.main import global_exception_handler


def test_internal_error_hides_exception_text_and_carries_ref():
    exc = internal_error("something_failed", RuntimeError("db password is hunter2"), alert_id="a1")
    assert isinstance(exc, HTTPException) and exc.status_code == 500
    assert "hunter2" not in exc.detail
    assert re.fullmatch(r"Internal server error \(ref [0-9a-f]{12}\)", exc.detail)


def test_request_ids_are_unique_hex():
    ids = {new_request_id() for _ in range(50)}
    assert len(ids) == 50 and all(re.fullmatch(r"[0-9a-f]{12}", i) for i in ids)


@pytest.mark.asyncio
async def test_global_handler_returns_request_id_without_leaking():
    app = FastAPI()
    app.add_exception_handler(Exception, global_exception_handler)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internal detail")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get("/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert "secret internal detail" not in resp.text
    assert re.fullmatch(r"[0-9a-f]{12}", body["request_id"])
    assert resp.headers["X-Request-ID"] == body["request_id"]


class _ExplodingDb:
    """Fake database whose every collection raises, to exercise the endpoint's error path."""

    def __getitem__(self, name):
        coll = AsyncMock()
        coll.find_one = AsyncMock(side_effect=RuntimeError("boom-secret"))
        return coll


@pytest.mark.asyncio
async def test_get_alert_500_does_not_leak_exception_text():
    with pytest.raises(HTTPException) as info:
        await alerts_module.get_alert("a1", db=_ExplodingDb(), user={"org_id": "default"})
    assert info.value.status_code == 500 and "boom-secret" not in info.value.detail


@pytest.mark.asyncio
async def test_ingest_502_is_not_rewrapped_as_500():
    class FakeService:
        errors = [{"stage": "fetch", "error": "splunk down"}]
        total_fetched = 0
        rules_run = 0

        def __init__(self, *a, **k):
            pass

        async def fetch_and_store_alerts(self):
            return []

    with patch.object(alerts_module, "IngestionService", FakeService):
        with pytest.raises(HTTPException) as info:
            await alerts_module.ingest_from_splunk(db=object(), _user={"org_id": "default", "role": "admin"})
    assert info.value.status_code == 502
