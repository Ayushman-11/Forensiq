from datetime import datetime, timedelta, timezone

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.config import settings
from app.normalization.noise import NoiseFilter
import app.services.ingestion as ingestion_mod
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
    raw = int((cursor - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)).timestamp())
    assert earliest == raw - raw % settings.INGEST_DEDUP_BUCKET_SECONDS  # aligned to the dedup bucket start


@pytest.mark.asyncio
async def test_first_run_uses_legacy_last_ingested_then_lookback(db):
    legacy = datetime(2026, 8, 1, tzinfo=timezone.utc)
    await db["ingestion_state"].insert_one({"_id": "last_ingested", "ts": legacy.isoformat()})
    splunk = FakeSplunk([])
    await _service(db, splunk).fetch_and_store_alerts()
    raw = int((legacy - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)).timestamp())
    assert int(splunk.queries[0][1]) == raw - raw % settings.INGEST_DEDUP_BUCKET_SECONDS

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


class GrowingSplunk(FakeSplunk):
    """Serves the current dataset, honoring earliest_time like Splunk does."""

    def __init__(self, rows):
        super().__init__()
        self.rows = rows

    async def search_raw_pages(self, query, earliest_time, latest_time="now", page_size=500, max_pages=20):
        self.queries.append((query, earliest_time))
        matching = [r for r in self.rows if datetime.fromisoformat(r["_time"]).timestamp() >= int(earliest_time)]
        matching = matching[: page_size * max_pages]  # Splunk boundary honors the page cap, oldest first
        for i in range(0, len(matching), page_size):
            yield matching[i:i + page_size]


def _fail_row(base, i, ip="45.33.32.156"):
    return {"_time": (base + timedelta(seconds=i)).isoformat(), "EventCode": "4625", "host": "LAB",
            "IpAddress": ip, "TargetUserName": "admin", "LogonType": "3", "_cd": f"1:{ip}:{i}"}


async def _cursor(db):
    return await db["ingestion_state"].find_one({"_id": "cursor:default:splunk"})


@pytest.mark.asyncio
async def test_cursor_never_regresses(db, splunk_rows):
    page = _rows(splunk_rows, "22")
    await _service(db, FakeSplunk([page])).fetch_and_store_alerts()
    before = (await _cursor(db))["ts"]
    older = [dict(r, _time="2000-01-01T00:00:00+00:00") for r in page]
    await _service(db, FakeSplunk([older])).fetch_and_store_alerts()
    assert (await _cursor(db))["ts"] == before


@pytest.mark.asyncio
async def test_truncated_cycle_resumes_exactly_at_cursor(db, monkeypatch):
    monkeypatch.setattr(settings, "INGEST_PAGE_SIZE", 2)
    monkeypatch.setattr(settings, "INGEST_MAX_PAGES", 1)
    base = datetime(2026, 8, 11, 6, 0, 7, tzinfo=timezone.utc)
    await _service(db, FakeSplunk([[_fail_row(base, 0), _fail_row(base, 1)]])).fetch_and_store_alerts()
    run = await db["ingestion_runs"].find_one({})
    cursor = await _cursor(db)
    assert run["truncated"] is True and cursor["truncated"] is True
    splunk = FakeSplunk([])
    await _service(db, splunk).fetch_and_store_alerts()
    assert int(splunk.queries[0][1]) == int(datetime.fromisoformat(cursor["ts"]).timestamp())


@pytest.mark.asyncio
async def test_non_truncated_next_cycle_is_bucket_aligned(db, splunk_rows):
    await _service(db, FakeSplunk([_rows(splunk_rows, "22")])).fetch_and_store_alerts()
    cursor = datetime.fromisoformat((await _cursor(db))["ts"])
    assert (await _cursor(db))["truncated"] is False
    splunk = FakeSplunk([])
    await _service(db, splunk).fetch_and_store_alerts()
    earliest = int(splunk.queries[0][1])
    assert earliest % settings.INGEST_DEDUP_BUCKET_SECONDS == 0
    assert earliest <= int((cursor - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)).timestamp())


@pytest.mark.asyncio
async def test_partial_store_failure_still_reports_stored_alerts(db, monkeypatch):
    base = datetime(2026, 8, 11, 6, 0, tzinfo=timezone.utc)
    rows = [_fail_row(base, i, ip) for ip in ("45.33.32.156", "185.220.101.4") for i in range(6)]
    real = ingestion_mod.build_alert_doc
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(*a, **kw)

    monkeypatch.setattr(ingestion_mod, "build_alert_doc", flaky)
    svc = _service(db, FakeSplunk([rows]))
    new = await svc.fetch_and_store_alerts()
    assert len(new) == 1 and await db["alerts"].count_documents({}) == 1
    assert (await db["ingestion_runs"].find_one({}))["status"] == "error"
    assert svc.errors[0]["stage"] == "store"
    assert await _cursor(db) is None


@pytest.mark.asyncio
async def test_slow_brute_force_counts_across_cycles(db, monkeypatch):
    bucket = settings.INGEST_DEDUP_BUCKET_SECONDS
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    base = datetime.fromtimestamp(now_epoch - now_epoch % bucket - 2 * bucket, tz=timezone.utc)  # bucket-aligned
    rows, reported = [], []
    for i in range(6):
        rows.append(_fail_row(base, i * 50))
        new = await _service(db, GrowingSplunk(rows)).fetch_and_store_alerts()
        reported += [a for a in new if a["rule_name"] == "brute_force_login"]
    stored = await db["alerts"].find({"rule_name": "brute_force_login"}).to_list(10)
    assert len(stored) == 1 and stored[0]["count"] == 6
    assert len(reported) == 1


async def _seed_cursor(db, ts, fetched, truncated=False):
    await db["ingestion_state"].insert_one(
        {"_id": "cursor:default:splunk", "ts": ts.isoformat(), "truncated": truncated, "fetched": fetched})


@pytest.mark.asyncio
async def test_alignment_only_when_previous_load_is_low(db, monkeypatch):
    monkeypatch.setattr(settings, "INGEST_PAGE_SIZE", 40)
    monkeypatch.setattr(settings, "INGEST_MAX_PAGES", 1)  # cap 40, quarter = 10
    cursor = datetime(2026, 8, 11, 6, 4, 50, tzinfo=timezone.utc)
    plain = int((cursor - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)).timestamp())

    await _seed_cursor(db, cursor, fetched=10)
    s1 = FakeSplunk([])
    await _service(db, s1).fetch_and_store_alerts()
    assert int(s1.queries[0][1]) == plain  # busy: not aligned
    assert plain % settings.INGEST_DEDUP_BUCKET_SECONDS != 0

    await db["ingestion_state"].update_one({"_id": "cursor:default:splunk"}, {"$set": {"fetched": 9}})
    s2 = FakeSplunk([])
    await _service(db, s2).fetch_and_store_alerts()
    assert int(s2.queries[0][1]) == plain - plain % settings.INGEST_DEDUP_BUCKET_SECONDS  # quiet: aligned


@pytest.mark.asyncio
async def test_sustained_load_does_not_flip_flop_truncation(db, monkeypatch):
    monkeypatch.setattr(settings, "INGEST_PAGE_SIZE", 20)
    monkeypatch.setattr(settings, "INGEST_MAX_PAGES", 1)  # cap 20
    monkeypatch.setattr(settings, "INGEST_INITIAL_LOOKBACK_HOURS", 24 * 365 * 10)
    base = datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc)
    # one row per 10 s for 15 minutes: the 120 s overlap window holds ~12 rows (fits), a 420 s window ~42 (does not)
    rows = [_fail_row(base, i * 10, f"10.0.{i % 250}.{i // 250}") for i in range(90)]
    cursors, flags = [], []
    for _ in range(14):
        await _service(db, GrowingSplunk(rows)).fetch_and_store_alerts()
        cursors.append(datetime.fromisoformat((await _cursor(db))["ts"]))
        flags.append((await _cursor(db))["truncated"])
    assert cursors == sorted(cursors)
    assert cursors[-1] == datetime.fromisoformat(rows[-1]["_time"])
    assert flags[-6:] == [False] * 6
