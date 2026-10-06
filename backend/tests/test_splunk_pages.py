import pytest

from app.infrastructure.siem.splunk import SplunkClient


def _client(rows):
    client = SplunkClient()
    calls = []

    async def submit(query, earliest, latest):
        calls.append(("submit", query, earliest, latest))
        return "sid1"

    async def poll(sid, **kw):
        return True

    async def get(sid, offset=0, limit=100):
        calls.append(("get", offset, limit))
        return rows[offset: offset + limit]

    client.submit_search, client.poll_search, client.get_results = submit, poll, get
    return client, calls


async def _collect(client, **kw):
    return [page async for page in client.search_raw_pages("index=windows", "100", **kw)]


@pytest.mark.asyncio
async def test_pages_until_short_page():
    client, calls = _client([{"i": i} for i in range(25)])
    pages = await _collect(client, page_size=10, max_pages=10)
    assert [len(p) for p in pages] == [10, 10, 5]
    assert [c[1] for c in calls if c[0] == "get"] == [0, 10, 20]


@pytest.mark.asyncio
async def test_stops_at_max_pages():
    client, _ = _client([{"i": i} for i in range(100)])
    pages = await _collect(client, page_size=10, max_pages=3)
    assert len(pages) == 3


@pytest.mark.asyncio
async def test_empty_result_yields_nothing():
    client, _ = _client([])
    assert await _collect(client) == []


@pytest.mark.asyncio
async def test_query_gets_search_prefix():
    client, calls = _client([])
    await _collect(client)
    assert calls[0][1].startswith("search ")
