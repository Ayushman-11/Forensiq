from datetime import datetime, timedelta, timezone

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.config import settings
from app.normalization.noise import NoiseFilter
from app.services.ingestion import IngestionService


class FakeSplunk:
    """Stands in for the Splunk HTTP boundary only; rows are real lab rows."""

    def __init__(self, pages=None, error=None):
        self.pages, self.error, self.queries, self.closed = pages or [], error, [], False

    async def search_raw_pages(self, query, earliest_time, latest_time="now", page_size=500, max_pages=20):
        self.queries.append((query, earliest_time))
        if self.error:
            raise self.error
        for page in self.pages:
            yield page

    async def close(self):
        self.closed = True


def _service(db, splunk, **kw):
    return IngestionService(db, "default", splunk_factory=lambda: splunk,
                            noise=NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH), **kw)


@pytest.fixture
def db():
    return AsyncMongoMockClient()["forensiq_test"]


def _rows(splunk_rows, *codes, per=3):
    return [r for c in codes for r in splunk_rows[c][:per]]


@pytest.mark.asyncio
async def test_real_rows_become_alerts_and_noise_is_counted(db, splunk_rows):
    page = _rows(splunk_rows, "22", "4648", "3")
    svc = _service(db, FakeSplunk([page]))
    new = await svc.fetch_and_store_alerts()

    assert svc.total_fetched == len(page)
    assert await db["alerts"].count_documents({}) == len(new) >= 1
    assert all(a["org_id"] == "default" and a["raw_event"] for a in new)

    run = await db["ingestion_runs"].find_one({})
    assert run["status"] == "ok" and run["fetched"] == len(page)
    assert run["suppressed"].get("machine_account_explicit_logon", 0) >= 1  # real 4648 machine-account noise


@pytest.mark.asyncio
async def test_rerun_is_idempotent(db, splunk_rows):
    page = _rows(splunk_rows, "22", "13")
    first = await _service(db, FakeSplunk([page])).fetch_and_store_alerts()
    second = await _service(db, FakeSplunk([page])).fetch_and_store_alerts()
    assert first and second == []
    assert await db["alerts"].count_documents({}) == len(first)


@pytest.mark.asyncio
async def test_cursor_advances_to_newest_processed_event_only_on_success(db, splunk_rows):
    page = _rows(splunk_rows, "22")
    await _service(db, FakeSplunk([page])).fetch_and_store_alerts()
    cursor = await db["ingestion_state"].find_one({"_id": "cursor:default:splunk"})
    newest = max(datetime.fromisoformat(r["_time"].replace("Z", "+00:00")) for r in page)
    assert datetime.fromisoformat(cursor["ts"]) == newest.astimezone(timezone.utc)

    boom = _service(db, FakeSplunk(error=RuntimeError("splunk down")))
    assert await boom.fetch_and_store_alerts() == []
    assert (await db["ingestion_state"].find_one({"_id": "cursor:default:splunk"}))["ts"] == cursor["ts"]
    assert boom.errors and boom.errors[0]["stage"] == "fetch"
    assert (await db["ingestion_runs"].find({"status": "error"}).to_list(10))


@pytest.mark.asyncio
async def test_next_cycle_queries_from_cursor_minus_overlap(db, splunk_rows):
    page = _rows(splunk_rows, "22")
    await _service(db, FakeSplunk([page])).fetch_and_store_alerts()
    splunk = FakeSplunk([])
    await _service(db, splunk).fetch_and_store_alerts()
    cursor = datetime.fromisoformat((await db["ingestion_state"].find_one({"_id": "cursor:default:splunk"}))["ts"])
    earliest = int(splunk.queries[0][1])
    assert earliest == int((cursor - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)).timestamp())


@pytest.mark.asyncio
async def test_first_run_uses_legacy_last_ingested_then_lookback(db):
    legacy = datetime(2026, 8, 1, tzinfo=timezone.utc)
    await db["ingestion_state"].insert_one({"_id": "last_ingested", "ts": legacy.isoformat()})
    splunk = FakeSplunk([])
    await _service(db, splunk).fetch_and_store_alerts()
    assert int(splunk.queries[0][1]) == int((legacy - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)).timestamp())

    db2 = AsyncMongoMockClient()["fresh"]
    splunk2 = FakeSplunk([])
    await _service(db2, splunk2).fetch_and_store_alerts()
    expected = datetime.now(timezone.utc) - timedelta(hours=settings.INGEST_INITIAL_LOOKBACK_HOURS)
    assert abs(int(splunk2.queries[0][1]) - int(expected.timestamp())) < 5


@pytest.mark.asyncio
async def test_failed_logons_aggregate_into_one_alert_per_source(db):
    base = datetime(2026, 8, 11, 6, 0, tzinfo=timezone.utc)

    def row(i, ip):
        return {"_time": (base + timedelta(seconds=i)).isoformat(), "EventCode": "4625", "host": "LAB",
                "IpAddress": ip, "TargetUserName": "admin", "LogonType": "3", "_cd": f"1:{ip}:{i}"}

    rows = [row(i, "45.33.32.156") for i in range(6)] + [row(i, "185.220.101.4") for i in range(5)] + [row(0, "91.240.118.2")]
    new = await _service(db, FakeSplunk([rows])).fetch_and_store_alerts()
    brute = [a for a in new if a["rule_name"] == "brute_force_login"]
    assert sorted(a["count"] for a in brute) == [5, 6]
    assert len({a["_id"] for a in brute}) == 2


@pytest.mark.asyncio
async def test_unmappable_rows_are_counted_not_fatal(db, splunk_rows):
    page = [{"garbage": "row"}] + _rows(splunk_rows, "22", per=1)
    svc = _service(db, FakeSplunk([page]))
    await svc.fetch_and_store_alerts()
    run = await db["ingestion_runs"].find_one({})
    assert run["unmapped"] == 1 and run["status"] == "ok"


@pytest.mark.asyncio
async def test_splunk_client_is_closed_even_on_error(db):
    splunk = FakeSplunk(error=RuntimeError("x"))
    await _service(db, splunk).fetch_and_store_alerts()
    assert splunk.closed
