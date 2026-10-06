"""
IngestionService – pulls real telemetry from Splunk, cleans and normalizes it,
applies detection rules, collapses repeats and upserts alerts idempotently.

Design (see docs/superpowers/specs/2026-10-06-forensiq-usp-pipeline-design.md):
  - One broad query per cycle, ordered by time, paginated.
  - Cursor = newest event time actually processed; re-queried with an overlap
    window so late-indexed events are caught. Stable alert IDs make that safe.
  - Cursor advances only when the whole cycle succeeds.
  - Writes are upserts ($setOnInsert), never find-then-insert.
  - One `ingestion_runs` document per cycle (counts, suppression reasons, lag).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.logging import logger
from app.infrastructure.siem.splunk import SplunkClient
from app.normalization.alerts import build_alert_doc
from app.normalization.canonical import CanonicalEvent
from app.normalization.clean import parse_ts
from app.normalization.dedup import RuleHit, aggregate_failed_logons, group_hits
from app.normalization.mappers import to_canonical
from app.normalization.noise import NoiseFilter
from app.services.detection_rules import DetectionRuleEngine

BRUTE_FORCE_RULE = "brute_force_login"
EVENT_CODES = ("1", "3", "13", "22", "4104", "4625", "4648", "4688")


def build_query() -> str:
    codes = " OR ".join(f"EventCode={c}" for c in EVENT_CODES)
    return f"search index={settings.SPLUNK_DETECTION_INDEX} | spath | search ({codes}) | sort 0 _time"


class IngestionService:
    STATE_COLLECTION = "ingestion_state"
    ALERTS_COLLECTION = "alerts"
    RUNS_COLLECTION = "ingestion_runs"

    def __init__(
        self,
        db: AsyncIOMotorDatabase,
        org_id: str = "default",
        splunk_factory: Callable[[], SplunkClient] = SplunkClient,
        noise: Optional[NoiseFilter] = None,
    ) -> None:
        self.db = db
        self.org_id = org_id
        self._splunk_factory = splunk_factory
        self.noise = noise or NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH)
        self.rules = DetectionRuleEngine().get_all_rules()
        self.errors: List[dict] = []
        self.total_fetched = 0
        self.rules_run = 0

    # -- cursor ---------------------------------------------------------

    @property
    def _cursor_id(self) -> str:
        return f"cursor:{self.org_id}:splunk"

    async def _load_cursor(self) -> tuple[Optional[datetime], bool]:
        for doc_id in (self._cursor_id, "last_ingested"):  # legacy doc keeps existing installs from re-ingesting
            doc = await self.db[self.STATE_COLLECTION].find_one({"_id": doc_id})
            if doc and doc.get("ts"):
                parsed = parse_ts(doc["ts"])
                if parsed:
                    return parsed, bool(doc.get("truncated", False))
        return None, False

    async def _save_cursor(self, newest: Optional[datetime], truncated: bool) -> None:
        if newest is None:
            return
        for doc_id in (self._cursor_id, "last_ingested"):
            existing = await self.db[self.STATE_COLLECTION].find_one({"_id": doc_id})
            prev = parse_ts(existing["ts"]) if existing and existing.get("ts") else None
            ts = max(prev, newest) if prev else newest  # never move the cursor backwards
            await self.db[self.STATE_COLLECTION].update_one(
                {"_id": doc_id}, {"$set": {"ts": ts.isoformat(), "truncated": truncated}}, upsert=True
            )

    def _earliest_epoch(self, cursor: Optional[datetime], truncated: bool = False) -> str:
        if cursor is None:
            start = datetime.now(timezone.utc) - timedelta(hours=settings.INGEST_INITIAL_LOOKBACK_HOURS)
            return str(int(start.timestamp()))
        if truncated:
            # Previous cycle hit the page cap: resume exactly at the cursor so progress is guaranteed.
            logger.warning("ingestion_truncated", cursor=cursor.isoformat())
            return str(int(cursor.timestamp()))
        start = cursor - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)
        epoch = int(start.timestamp())
        bucket = settings.INGEST_DEDUP_BUCKET_SECONDS
        # Align to the dedup bucket start so every cycle sees in-flight buckets completely.
        return str(epoch - epoch % bucket)

    # -- pipeline stages ------------------------------------------------

    async def _collect(self, splunk: SplunkClient, earliest: str, run: dict):
        events: List[CanonicalEvent] = []
        newest: Optional[datetime] = None
        pages = 0
        last_page_len = 0
        async for page in splunk.search_raw_pages(
            build_query(), earliest_time=earliest, latest_time="now",
            page_size=settings.INGEST_PAGE_SIZE, max_pages=settings.INGEST_MAX_PAGES,
        ):
            pages += 1
            last_page_len = len(page)
            for row in page:
                run["fetched"] += 1
                ts = parse_ts(row.get("_time"))
                if ts and (newest is None or ts > newest):
                    newest = ts
                try:
                    event = to_canonical(row)
                except Exception as exc:  # a malformed row must not fail the cycle
                    logger.warning("ingestion_row_unmappable", error=str(exc))
                    event = None
                if event is None:
                    run["unmapped"] += 1
                    continue
                reason = self.noise.reason(event)
                if reason:
                    run["suppressed"][reason] = run["suppressed"].get(reason, 0) + 1
                    continue
                events.append(event)
        run["truncated"] = pages >= settings.INGEST_MAX_PAGES and last_page_len >= settings.INGEST_PAGE_SIZE
        return events, newest

    def _detect(self, events: List[CanonicalEvent], run: dict) -> List[RuleHit]:
        hits: List[RuleHit] = []
        brute = next((r for r in self.rules if r.name == BRUTE_FORCE_RULE), None)
        for event in events:
            for rule in self.rules:
                if rule.name == BRUTE_FORCE_RULE or rule.match_fn is None:
                    continue
                try:
                    matched = rule.match_fn(event.fields)
                except Exception as exc:
                    run["rule_errors"] += 1
                    logger.error("ingestion_rule_error", rule=rule.name, error=str(exc))
                    continue
                if matched:
                    hits.append(RuleHit(rule, event))
        if brute is not None:
            for event, count in aggregate_failed_logons(
                events, settings.BRUTE_FORCE_THRESHOLD, settings.INGEST_DEDUP_BUCKET_SECONDS,
            ):
                hits.append(RuleHit(brute, event, count))
        self.rules_run = len(self.rules)
        return hits

    async def _store(self, groups, run: dict, new_alerts: List[dict]) -> List[dict]:
        collection = self.db[self.ALERTS_COLLECTION]
        for group in groups:
            doc = build_alert_doc(group, self.org_id, self.noise)
            insert_only = {k: v for k, v in doc.items() if k not in ("_id", "count", "last_seen")}
            result = await collection.update_one(
                {"_id": doc["_id"]},
                {"$setOnInsert": insert_only, "$max": {"count": doc["count"], "last_seen": doc["last_seen"]}},
                upsert=True,
            )
            if result.upserted_id is not None:
                new_alerts.append(doc)
                run["alerts_new"] += 1
            else:
                run["alerts_seen"] += 1
        return new_alerts

    # -- public entry point ---------------------------------------------

    async def fetch_and_store_alerts(self, limit: Optional[int] = None) -> List[dict]:
        run = {
            "_id": str(uuid.uuid4()), "org_id": self.org_id, "started_at": datetime.now(timezone.utc),
            "status": "ok", "fetched": 0, "unmapped": 0, "suppressed": {}, "rule_errors": 0,
            "hits": 0, "alerts_new": 0, "alerts_seen": 0, "truncated": False, "lag_seconds": None, "errors": [],
        }
        self.errors, self.total_fetched = [], 0
        new_alerts: List[dict] = []
        stage = "fetch"
        splunk = self._splunk_factory()
        try:
            cursor, was_truncated = await self._load_cursor()
            events, newest = await self._collect(splunk, self._earliest_epoch(cursor, was_truncated), run)
            stage = "detect"
            hits = self._detect(events, run)
            run["hits"] = len(hits)
            stage = "store"
            groups = group_hits(hits, self.org_id, settings.INGEST_DEDUP_BUCKET_SECONDS)
            await self._store(groups, run, new_alerts)
            await self._save_cursor(newest, run["truncated"])  # only reached when every stage succeeded
            if newest:
                run["lag_seconds"] = max(0, int((datetime.now(timezone.utc) - newest).total_seconds()))
        except Exception as exc:
            run["status"] = "error"
            self.errors.append({"stage": stage, "error": str(exc)})
            run["errors"] = list(self.errors)
            logger.error("ingestion_cycle_failed", stage=stage, error=str(exc))
        finally:
            await splunk.close()
            run["finished_at"] = datetime.now(timezone.utc)
            self.total_fetched = run["fetched"]
            try:
                await self.db[self.RUNS_COLLECTION].insert_one(run)
            except Exception as exc:  # health bookkeeping must never mask the real result
                logger.error("ingestion_run_record_failed", error=str(exc))

        logger.info(
            "ingestion_complete", fetched=run["fetched"], unmapped=run["unmapped"],
            suppressed=sum(run["suppressed"].values()), alerts_new=run["alerts_new"],
            alerts_seen=run["alerts_seen"], status=run["status"],
        )
        return new_alerts
