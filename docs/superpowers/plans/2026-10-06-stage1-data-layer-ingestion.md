# Stage 1: Data Layer and Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the ad-hoc Splunk-to-alert code with a normalization layer (canonical events, one IOC extractor, data-driven noise suppression, deduplication with stable IDs) and a reliable ingestion loop (cursor, pagination, idempotent writes, single-poller lease, health records).

**Architecture:** Raw Splunk rows go through `app/normalization/` (clean, map to `CanonicalEvent`, suppress noise, extract IOCs). Existing detection rules keep running on cleaned fields (stage 2 replaces them with Sigma-style YAML). Hits are grouped into alerts with stable IDs and upserted idempotently. `IngestionService` owns the cursor and records one `ingestion_runs` document per cycle. No mock data anywhere.

**Tech Stack:** Python 3.11+, FastAPI, Motor/MongoDB, Pydantic v2, PyYAML, tldextract (bundled public-suffix snapshot, offline), pytest + pytest-asyncio + mongomock-motor.

**Spec:** `docs/superpowers/specs/2026-10-06-forensiq-usp-pipeline-design.md` (sections 4 and 5.1; stage 1 of section 9). Stage 2 (Sigma rules, eval harness) and stage 3 (agents) get their own plans.

## Global Constraints

- No mock layer: tests use real Splunk rows exported from the repo's own lab data (`mongo_dump_json/alerts.json`). Pure logic that has no real-row equivalent (for example, aggregation counting) may be unit-tested with constructed `CanonicalEvent` objects.
- Run all commands from `D:\forensiq\Forensiq\backend` with `./venv/Scripts/python.exe`.
- All new datetimes are timezone-aware UTC in code. Values read back from Mongo are naive UTC; compare accordingly.
- Raw rows are never discarded: the original row stays in the alert as `raw_event` (first event) and `raw_events` (up to 20).
- Every suppressed event is counted with a reason (`ingestion_runs.suppressed`); nothing is dropped silently.
- Existing alert document field names consumed by agents and the frontend must keep working: `host`, `user`, `source_ip`, `dest_ip`, `dest_port`, `process_name`, `command_line`, `parent_process`, `registry_key`, `dns_query`, `hashes`, `logon_type`, `failure_reason`, `event_code`, `created_at`, `detected_at`, `extracted_iocs`, `raw_event`, `rule_name`, `mitre_technique`, `mitre_tactic`, `alert_type`, `severity`, `status`, `ai_confidence`, `source_siem`, `org_id`.
- Existing 57 tests must still pass after every task.
- End every commit message with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Stage-1 decisions fixed here: rule-predicate exceptions are counted (`rule_errors`) but do not block the cursor; Splunk fetch, mapping-infrastructure and database errors do block it.

## File Structure

| File | Responsibility |
|---|---|
| `app/normalization/__init__.py` | package marker, re-exports |
| `app/normalization/clean.py` | value cleaning, timestamp parsing, XML field recovery, account/host/path/hash helpers, raw event ID |
| `app/normalization/canonical.py` | `CanonicalEvent` Pydantic model |
| `app/normalization/mappers.py` | `to_canonical(raw)` for Sysmon, Security and PowerShell events |
| `app/normalization/ioc.py` | single IOC extractor (IPs via `ipaddress`, domains via public suffix list, hashes, URLs, defang) |
| `app/normalization/noise.py` | `NoiseFilter` driven by `config/noise.yaml` |
| `app/normalization/dedup.py` | `RuleHit`, `AlertGroup`, stable IDs, grouping, failed-logon aggregation |
| `app/normalization/alerts.py` | `build_alert_doc(group, org_id, noise)` |
| `config/noise.yaml` | suppression policy |
| `app/services/ingestion.py` | rewritten `IngestionService` |
| `app/services/lease.py` | Mongo lease for single-poller |
| `app/services/poller.py` | uses lease, per-cycle service, bounded investigations |
| `app/infrastructure/siem/splunk.py` | add `search_raw_pages` |
| `app/database/indexes.py` | `ensure_indexes(db)` |
| `app/api/v1/endpoints/dashboard.py` | `GET /ingestion-health` |
| `scripts/export_fixture_rows.py` | exports real rows into `tests/fixtures/splunk_rows.json` |
| `tests/test_norm_*.py`, `tests/test_ingestion_*.py`, `tests/test_lease_poller.py` | tests |

---

### Task 1: Branch, dependencies, settings, real-row fixtures

**Files:**
- Modify: `backend/pyproject.toml`, `backend/app/core/config.py`, `backend/.env.example`, `backend/tests/conftest.py`
- Create: `backend/scripts/export_fixture_rows.py`, `backend/tests/fixtures/splunk_rows.json` (generated), `backend/tests/test_norm_fixtures.py`

**Interfaces:**
- Produces: settings `INGEST_OVERLAP_SECONDS: int = 120`, `INGEST_MAX_PAGES: int = 20`, `INGEST_PAGE_SIZE: int = 500`, `INGEST_INITIAL_LOOKBACK_HOURS: int = 168`, `INGEST_DEDUP_BUCKET_SECONDS: int = 300`, `BRUTE_FORCE_THRESHOLD: int = 5`, `NOISE_CONFIG_PATH: str = "config/noise.yaml"`, `INVESTIGATION_CONCURRENCY: int = 3`, `POLLER_LEASE_TTL_SECONDS: int = 90`.
- Produces: pytest fixture `splunk_rows` returning `dict[str, list[dict]]` keyed by event code string (`"1"`, `"3"`, `"13"`, `"22"`, `"4104"`, `"4648"`).

- [ ] **Step 1: Create the feature branch**

```bash
cd /d/forensiq/Forensiq && git checkout -b feat/stage1-data-layer
```

- [ ] **Step 2: Add the dependency and install it**

In `backend/pyproject.toml`, add `"pyyaml>=6.0",` and `"tldextract>=5.1",` to `dependencies`. Then:

```bash
cd backend && ./venv/Scripts/python.exe -m pip install -q "tldextract>=5.1" "pyyaml>=6.0"
```

- [ ] **Step 3: Add settings**

In `backend/app/core/config.py`, add inside `Settings` after the `IOC_CACHE_TTL_HOURS` field:

```python
    # Ingestion pipeline
    INGEST_OVERLAP_SECONDS: int = Field(default=120, description="Re-query overlap to catch late-indexed events")
    INGEST_MAX_PAGES: int = Field(default=20, description="Max result pages fetched per ingestion cycle")
    INGEST_PAGE_SIZE: int = Field(default=500, description="Rows per Splunk result page")
    INGEST_INITIAL_LOOKBACK_HOURS: int = Field(default=168, description="First-run lookback window in hours")
    INGEST_DEDUP_BUCKET_SECONDS: int = Field(default=300, description="Time bucket for collapsing repeated detections")
    BRUTE_FORCE_THRESHOLD: int = Field(default=5, description="Failed logons per bucket and source that raise an alert")
    NOISE_CONFIG_PATH: str = Field(default="config/noise.yaml", description="Noise suppression policy file")
    INVESTIGATION_CONCURRENCY: int = Field(default=3, description="Max concurrent auto-investigations")
    POLLER_LEASE_TTL_SECONDS: int = Field(default=90, description="Single-poller lease time to live")
```

Append to `backend/.env.example`:

```
# Ingestion pipeline (defaults shown)
FORENSIQ_INGEST_OVERLAP_SECONDS=120
FORENSIQ_INGEST_MAX_PAGES=20
FORENSIQ_INGEST_PAGE_SIZE=500
FORENSIQ_BRUTE_FORCE_THRESHOLD=5
FORENSIQ_VT_API_KEY=
```

- [ ] **Step 4: Write the fixture export script**

Create `backend/scripts/export_fixture_rows.py`:

```python
"""
Exports a few real Splunk rows per EventCode from the committed lab dump into
tests/fixtures/splunk_rows.json. The dump stores each alert's original row as
`raw_event` (underscore-prefixed Splunk keys were stripped), so `_time` is
restored from the alert's created_at.

Usage (from backend/): ./venv/Scripts/python.exe scripts/export_fixture_rows.py
"""

import json
from pathlib import Path

DUMP = Path("mongo_dump_json/alerts.json")
OUT = Path("tests/fixtures/splunk_rows.json")
PER_CODE = 3


def _iso(value) -> str:
    if isinstance(value, dict):
        value = value.get("$date")
    return str(value)


def main() -> None:
    alerts = json.loads(DUMP.read_text(encoding="utf-8"))
    rows: dict[str, list[dict]] = {}
    for alert in alerts:
        raw = alert.get("raw_event")
        code = str(alert.get("event_code") or "")
        if not raw or not code:
            continue
        bucket = rows.setdefault(code, [])
        if len(bucket) >= PER_CODE:
            continue
        row = dict(raw)
        row["_time"] = _iso(alert.get("created_at"))
        bucket.append(row)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print({code: len(items) for code, items in rows.items()})


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Add the fixture to conftest**

Append to `backend/tests/conftest.py`:

```python
import json
from pathlib import Path


@pytest.fixture(scope="session")
def splunk_rows():
    """Real Splunk rows (from the lab dump) keyed by EventCode string."""
    path = Path(__file__).parent / "fixtures" / "splunk_rows.json"
    return json.loads(path.read_text(encoding="utf-8"))
```

- [ ] **Step 6: Write the failing test, generate the fixture, verify**

Create `backend/tests/test_norm_fixtures.py`:

```python
def test_fixture_has_real_rows_for_each_supported_event_code(splunk_rows):
    for code in ("1", "3", "13", "22", "4104", "4648"):
        assert splunk_rows[code], f"no fixture rows for EventCode {code}"
        assert splunk_rows[code][0]["EventCode"] == code
        assert splunk_rows[code][0]["_time"]
```

Run (fails: fixture missing), generate, rerun:

```bash
cd backend && ./venv/Scripts/python.exe -m pytest tests/test_norm_fixtures.py -q
./venv/Scripts/python.exe scripts/export_fixture_rows.py
./venv/Scripts/python.exe -m pytest tests/test_norm_fixtures.py -q
```

Expected: first run FAIL (FileNotFoundError), script prints counts for six codes, second run PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/pyproject.toml backend/app/core/config.py backend/.env.example backend/scripts/export_fixture_rows.py backend/tests/fixtures backend/tests/conftest.py backend/tests/test_norm_fixtures.py
git commit -m "feat: add ingestion settings, tldextract/pyyaml deps and real-row fixtures"
```

---

### Task 2: Cleaning helpers (`clean.py`)

**Files:**
- Create: `backend/app/normalization/__init__.py`, `backend/app/normalization/clean.py`
- Test: `backend/tests/test_norm_clean.py`

**Interfaces:**
- Produces (all in `app.normalization.clean`):
  - `clean_value(value) -> str | None`
  - `xml_fields(raw: dict) -> dict[str, str]`
  - `merged_fields(raw: dict) -> dict[str, str]` (Splunk top-level fields win; XML fills gaps; null-ish values dropped)
  - `parse_ts(value) -> datetime | None` (tz-aware UTC)
  - `split_account(account) -> tuple[str | None, str | None]` returns `(domain, user)`
  - `host_key(host) -> str | None`
  - `basename(path) -> str | None`
  - `parse_hashes(value) -> dict[str, str]`
  - `raw_event_id(raw: dict) -> str` (32 hex chars)

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_norm_clean.py`:

```python
from datetime import timezone

from app.normalization.clean import (
    basename, clean_value, host_key, merged_fields, parse_hashes,
    parse_ts, raw_event_id, split_account, xml_fields,
)


def test_clean_value_treats_dash_and_empty_as_none():
    assert clean_value("-") is None
    assert clean_value("  ") is None
    assert clean_value(None) is None
    assert clean_value("(NULL)") is None
    assert clean_value("  abc ") == "abc"
    assert clean_value(0) == "0"


def test_parse_ts_converts_offsets_to_utc():
    ts = parse_ts("2026-08-11T12:07:25.875+05:30")
    assert ts.tzinfo is not None
    assert ts.utcoffset().total_seconds() == 0
    assert (ts.hour, ts.minute) == (6, 37)


def test_parse_ts_handles_z_naive_epoch_and_garbage():
    assert parse_ts("2026-08-11T06:37:25Z").tzinfo == timezone.utc
    assert parse_ts("2026-08-11 06:37:25").tzinfo == timezone.utc
    assert parse_ts("1786430245").year == 2026
    assert parse_ts("not a time") is None
    assert parse_ts(None) is None


def test_split_account_variants():
    assert split_account("Ayush\\ayush") == ("Ayush", "ayush")
    assert split_account("ayush@corp.local") == ("corp.local", "ayush")
    assert split_account("ayush") == (None, "ayush")
    assert split_account("-") == (None, None)


def test_host_key_lowercases_and_strips_domain():
    assert host_key("AYUSH-VICTUS.corp.local") == "ayush-victus"
    assert host_key("Ayush") == "ayush"
    assert host_key("10.1.2.3") == "10.1.2.3"
    assert host_key("-") is None


def test_basename_handles_windows_paths():
    assert basename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert basename(None) is None


def test_parse_hashes_sysmon_format():
    h = parse_hashes("MD5=ABCDEF0123456789ABCDEF0123456789,SHA256=" + "A" * 64 + ",IMPHASH=zz")
    assert h["md5"] == "abcdef0123456789abcdef0123456789"
    assert h["sha256"] == "a" * 64
    assert "imphash" not in h  # non-hex values are dropped


def test_xml_fields_recovers_values_missing_from_top_level():
    raw = {"EventData_Xml": "<Data Name='Image'>C:\\a.exe</Data><Data Name='User'>Ayush\\ayush</Data>"}
    assert xml_fields(raw) == {"Image": "C:\\a.exe", "User": "Ayush\\ayush"}


def test_merged_fields_prefers_top_level_and_fills_from_xml():
    raw = {"Image": "C:\\top.exe", "X": "-", "EventData_Xml": "<Data Name='Image'>C:\\xml.exe</Data><Data Name='X'>val</Data>"}
    merged = merged_fields(raw)
    assert merged["Image"] == "C:\\top.exe"
    assert merged["X"] == "val"


def test_raw_event_id_stable_and_uses_cd_like_legacy_ids():
    import hashlib
    row = {"_cd": "12:345", "_time": "2026-08-11T06:37:25Z"}
    assert raw_event_id(row) == hashlib.sha256(b"12:345").hexdigest()[:32]
    no_cd_a = {"EventCode": "1", "_time": "t1", "Image": "a"}
    no_cd_b = {"EventCode": "1", "_time": "t1", "Image": "b"}
    assert raw_event_id(no_cd_a) == raw_event_id(dict(no_cd_a))
    assert raw_event_id(no_cd_a) != raw_event_id(no_cd_b)


def test_real_rows_have_recoverable_fields(splunk_rows):
    for code, rows in splunk_rows.items():
        for row in rows:
            merged = merged_fields(row)
            assert merged["EventCode"] == code
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_clean.py -q`
Expected: FAIL with `ModuleNotFoundError: app.normalization`.

- [ ] **Step 3: Implement**

Create `backend/app/normalization/__init__.py` (empty file).

Create `backend/app/normalization/clean.py`:

```python
"""Value cleaning and field-recovery helpers shared by all mappers."""

from __future__ import annotations

import hashlib
import html
import json
import ntpath
import re
from datetime import datetime, timezone
from typing import Any

_NULLS = {"", "-", "null", "none", "(null)", "n/a"}
_XML_DATA_RE = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]>(.*?)</Data>", re.S)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_IPV4_ONLY_RE = re.compile(r"^[\d.]+$")


def clean_value(value: Any) -> str | None:
    """Strip whitespace and map Splunk/Windows 'empty' markers to None."""
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    return None if text.lower() in _NULLS else text


def xml_fields(raw: dict) -> dict[str, str]:
    """Recover `<Data Name='X'>value</Data>` pairs from the EventData_Xml blob."""
    xml = raw.get("EventData_Xml") or ""
    return {name: html.unescape(value) for name, value in _XML_DATA_RE.findall(xml)}


def merged_fields(raw: dict) -> dict[str, str]:
    """Splunk top-level fields win; the XML blob fills gaps; null-ish values are dropped."""
    merged: dict[str, str] = {}
    for key, value in xml_fields(raw).items():
        cleaned = clean_value(value)
        if cleaned is not None:
            merged[key] = cleaned
    for key, value in raw.items():
        if key.startswith("_") or key in ("EventData_Xml", "System_Props_Xml"):
            continue
        cleaned = clean_value(value)
        if cleaned is not None:
            merged[key] = cleaned
    return merged


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_ts(value: Any) -> datetime | None:
    """Parse ISO-8601 (with or without offset, 'Z') or epoch seconds into aware UTC."""
    text = clean_value(value)
    if text is None:
        return None
    try:
        return _aware(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        pass
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def split_account(account: Any) -> tuple[str | None, str | None]:
    """'DOMAIN\\user' or 'user@domain' -> (domain, user); bare name -> (None, name)."""
    text = clean_value(account)
    if text is None:
        return None, None
    if "\\" in text:
        domain, _, user = text.partition("\\")
        return clean_value(domain), clean_value(user)
    if "@" in text:
        user, _, domain = text.partition("@")
        return clean_value(domain), clean_value(user)
    return None, text


def host_key(host: Any) -> str | None:
    """Lowercase short host name used for matching/dedup (IPs are kept whole)."""
    text = clean_value(host)
    if text is None:
        return None
    text = text.lower().rstrip(".")
    return text if _IPV4_ONLY_RE.match(text) else text.split(".")[0]


def basename(path: Any) -> str | None:
    text = clean_value(path)
    return ntpath.basename(text) or None if text else None


def parse_hashes(value: Any) -> dict[str, str]:
    """Parse Sysmon 'MD5=..,SHA256=..' into {algo: lowercase_hex}; non-hex values dropped."""
    text = clean_value(value)
    hashes: dict[str, str] = {}
    if not text:
        return hashes
    for segment in text.split(","):
        algo, _, digest = segment.partition("=")
        digest = digest.strip()
        if digest and _HEX_RE.match(digest):
            hashes[algo.strip().lower()] = digest.lower()
    return hashes


def raw_event_id(raw: dict) -> str:
    """Stable ID for one Splunk row. Uses `_cd` exactly like legacy IDs so existing alerts still dedup."""
    cd = clean_value(raw.get("_cd"))
    if cd:
        return hashlib.sha256(cd.encode()).hexdigest()[:32]
    body = {k: v for k, v in raw.items() if not k.startswith("_")}
    body["_time"] = raw.get("_time")
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:32]
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_clean.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/normalization backend/tests/test_norm_clean.py
git commit -m "feat(normalization): add cleaning helpers with XML field recovery"
```

---

### Task 3: Canonical event and mappers

**Files:**
- Create: `backend/app/normalization/canonical.py`, `backend/app/normalization/mappers.py`
- Test: `backend/tests/test_norm_mappers.py`

**Interfaces:**
- Consumes: everything from Task 2 `clean.py`.
- Produces:
  - `class CanonicalEvent(BaseModel)` with fields: `event_id: str`, `ts: datetime`, `host: str | None`, `host_key: str | None`, `user: str | None`, `user_display: str | None`, `account_domain: str | None`, `event_code: str`, `source: str`, `process: str | None` (basename, lowercase), `process_path: str | None`, `parent: str | None`, `parent_path: str | None`, `command_line: str | None`, `hashes: dict[str, str]`, `src_ip`, `dst_ip`, `dst_port: int | None`, `protocol`, `initiated: bool | None`, `query_name`, `query_results`, `registry_key`, `registry_details`, `logon_type`, `failure_reason`, `workstation`, `subject_user`, `target_user`, `target_domain`, `script_block`, `fields: dict[str, str]` (merged_fields), `raw: dict`, `cleaning_notes: list[str]`.
  - `to_canonical(raw: dict) -> CanonicalEvent | None` (None when EventCode or `_time` is unusable).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_norm_mappers.py`:

```python
from app.normalization.mappers import to_canonical


def test_dns_event_from_real_row(splunk_rows):
    ev = to_canonical(splunk_rows["22"][0])
    assert ev.event_code == "22"
    assert ev.query_name == "raw.githubusercontent.com"
    assert ev.process == "wslservice.exe"
    assert ev.ts.tzinfo is not None
    assert ev.host_key
    assert ev.raw == splunk_rows["22"][0]


def test_network_event_from_real_row(splunk_rows):
    ev = to_canonical(splunk_rows["3"][0])
    assert ev.dst_ip == "34.206.0.173"
    assert ev.dst_port == 4318
    assert ev.initiated is True
    assert ev.process == "gk_3_1_72.exe"


def test_process_event_from_real_row(splunk_rows):
    ev = to_canonical(splunk_rows["1"][0])
    assert ev.process == "powershell.exe"
    assert "generate_events.ps1" in ev.command_line


def test_registry_event_from_real_row(splunk_rows):
    ev = to_canonical(splunk_rows["13"][0])
    assert "currentversion\\run" in ev.registry_key.lower()
    assert ev.process == "chrome.exe"


def test_explicit_credential_event_keeps_subject_and_target(splunk_rows):
    ev = to_canonical(splunk_rows["4648"][0])
    assert ev.subject_user.endswith("$")
    assert ev.target_user
    assert ev.user == ev.subject_user


def test_script_block_event(splunk_rows):
    ev = to_canonical(splunk_rows["4104"][0])
    assert "generate_events.ps1" in ev.script_block


def test_every_fixture_row_maps(splunk_rows):
    for code, rows in splunk_rows.items():
        for row in rows:
            ev = to_canonical(row)
            assert ev is not None and ev.event_code == code
            assert len(ev.event_id) == 32


def test_missing_time_or_code_returns_none():
    assert to_canonical({"EventCode": "1"}) is None
    assert to_canonical({"_time": "2026-08-11T06:37:25Z"}) is None


def test_dash_values_become_none():
    ev = to_canonical({"EventCode": "3", "_time": "2026-08-11T06:37:25Z", "SourceIp": "-", "DestinationIp": "8.8.8.8", "DestinationPort": "53"})
    assert ev.src_ip is None and ev.dst_ip == "8.8.8.8"
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_mappers.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement the model**

Create `backend/app/normalization/canonical.py`:

```python
"""SIEM-agnostic cleaned event produced by the mappers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CanonicalEvent(BaseModel):
    event_id: str
    ts: datetime
    event_code: str
    source: str = "splunk"

    host: str | None = None
    host_key: str | None = None
    user: str | None = None
    user_display: str | None = None
    account_domain: str | None = None

    process: str | None = None
    process_path: str | None = None
    parent: str | None = None
    parent_path: str | None = None
    command_line: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)

    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    initiated: bool | None = None

    query_name: str | None = None
    query_results: str | None = None
    registry_key: str | None = None
    registry_details: str | None = None

    logon_type: str | None = None
    failure_reason: str | None = None
    workstation: str | None = None
    subject_user: str | None = None
    target_user: str | None = None
    target_domain: str | None = None
    script_block: str | None = None

    fields: dict[str, str] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    cleaning_notes: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Implement the mappers**

Create `backend/app/normalization/mappers.py`:

```python
"""Map raw Splunk rows (Sysmon, Windows Security, PowerShell) to CanonicalEvent."""

from __future__ import annotations

from app.normalization.canonical import CanonicalEvent
from app.normalization.clean import (
    basename, clean_value, host_key, merged_fields, parse_hashes,
    parse_ts, raw_event_id, split_account,
)


def _int(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.lower() in ("true", "1", "yes")


def to_canonical(raw: dict) -> CanonicalEvent | None:
    """Return a cleaned event, or None when the row has no usable EventCode or `_time`."""
    fields = merged_fields(raw)
    code = fields.get("EventCode") or fields.get("EventID")
    ts = parse_ts(raw.get("_time"))
    if code is None or ts is None:
        return None

    notes: list[str] = []
    if "EventCode" not in raw or clean_value(raw.get("EventCode")) is None:
        notes.append("event_code_recovered_from_xml_or_eventid")
    recovered = sorted(k for k in fields if clean_value(raw.get(k)) is None and k not in ("EventCode", "EventID"))
    if recovered and raw.get("EventData_Xml"):
        notes.append(f"fields_recovered_from_xml:{len(recovered)}")

    f = fields.get
    host = f("host") or f("Computer") or f("ComputerName")

    image = f("Image") or f("NewProcessName") or f("ProcessName")
    parent = f("ParentImage") or f("ParentProcessName")

    domain, user = split_account(f("User"))
    subject_user = f("SubjectUserName")
    target_user = f("TargetUserName")
    target_domain = f("TargetDomainName")
    user_display = f("User")

    if code in ("4625",):
        user, domain = target_user, target_domain
        user_display = target_user
    elif code in ("4648", "4688", "4624"):
        user, domain = subject_user, f("SubjectDomainName")
        user_display = subject_user

    hashes = parse_hashes(f("Hashes"))

    return CanonicalEvent(
        event_id=raw_event_id(raw),
        ts=ts,
        event_code=code,
        source=str(raw.get("source") or "splunk"),
        host=host,
        host_key=host_key(host),
        user=user,
        user_display=user_display,
        account_domain=domain,
        process=(basename(image) or "").lower() or None,
        process_path=image,
        parent=(basename(parent) or "").lower() or None,
        parent_path=parent,
        command_line=f("CommandLine"),
        hashes=hashes,
        src_ip=f("SourceIp") or f("IpAddress"),
        dst_ip=f("DestinationIp"),
        dst_port=_int(f("DestinationPort")),
        protocol=(f("Protocol") or "").lower() or None,
        initiated=_bool(f("Initiated")),
        query_name=(f("QueryName") or "").lower().rstrip(".") or None,
        query_results=f("QueryResults"),
        registry_key=f("TargetObject"),
        registry_details=f("Details"),
        logon_type=f("LogonType"),
        failure_reason=f("FailureReason") or f("Status"),
        workstation=f("WorkstationName"),
        subject_user=subject_user,
        target_user=target_user,
        target_domain=target_domain,
        script_block=f("ScriptBlockText"),
        fields=fields,
        raw=raw,
        cleaning_notes=notes,
    )
```

- [ ] **Step 5: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_mappers.py -q`
Expected: all PASS. If a literal assertion fails, print the fixture row (`splunk_rows[code][0]`) and fix the mapper field name, not the test.

- [ ] **Step 6: Commit**

```bash
git add backend/app/normalization/canonical.py backend/app/normalization/mappers.py backend/tests/test_norm_mappers.py
git commit -m "feat(normalization): add CanonicalEvent and Sysmon/Security/PowerShell mappers"
```

---

### Task 4: Single IOC extractor

**Files:**
- Create: `backend/app/normalization/ioc.py`
- Test: `backend/tests/test_norm_ioc.py`

**Interfaces:**
- Consumes: `CanonicalEvent` (Task 3).
- Produces (`app.normalization.ioc`):
  - `public_ip(value: str | None) -> str | None`
  - `public_domain(value: str | None, allow_file_tlds: bool = False) -> str | None`
  - `defang(text: str) -> str`
  - `ioc_kind(ioc: str) -> Literal["ip", "domain", "hash"]`
  - `extract_iocs(event: CanonicalEvent, is_benign_domain: Callable[[str], bool] | None = None) -> list[str]` (ordered, deduplicated, lowercase domains and hashes).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_norm_ioc.py`:

```python
from app.normalization.ioc import defang, extract_iocs, ioc_kind, public_domain, public_ip
from app.normalization.mappers import to_canonical


def test_public_ip_rejects_all_non_global_ranges():
    for bad in ("10.1.1.1", "192.168.0.5", "172.20.1.1", "127.0.0.1", "169.254.3.3",
                "100.64.0.1", "224.0.0.251", "::1", "fe80::1", "0.0.0.0", "not-an-ip", None, "-"):
        assert public_ip(bad) is None, bad
    assert public_ip("8.8.8.8") == "8.8.8.8"
    assert public_ip("::ffff:8.8.4.4") == "8.8.4.4"
    assert public_ip("2606:4700::1111") == "2606:4700::1111"


def test_public_domain_uses_public_suffix_list():
    assert public_domain("Raw.GitHubUserContent.com.") == "raw.githubusercontent.com"
    assert public_domain("wpad") is None
    assert public_domain("printer.corp.local") is None
    assert public_domain("calc.exe") is None
    assert public_domain("script.py") is None
    assert public_domain("script.py", allow_file_tlds=True) == "script.py"
    assert public_domain("evil.co.uk") == "evil.co.uk"


def test_defang():
    assert defang("hxxps://evil[.]com/x") == "https://evil.com/x"


def test_ioc_kind():
    assert ioc_kind("8.8.8.8") == "ip"
    assert ioc_kind("a" * 64) == "hash"
    assert ioc_kind("evil.com") == "domain"


def test_dns_event_yields_domain_and_public_resolved_ips(splunk_rows):
    ev = to_canonical(splunk_rows["22"][0])
    iocs = extract_iocs(ev)
    assert "raw.githubusercontent.com" in iocs
    assert "185.199.109.133" in iocs


def test_network_event_yields_public_destination_only(splunk_rows):
    ev = to_canonical(splunk_rows["3"][0])
    iocs = extract_iocs(ev)
    assert "34.206.0.173" in iocs
    assert not any(i.startswith("10.") for i in iocs)


def test_command_line_urls_and_ips_are_extracted():
    ev = to_canonical({
        "_time": "2026-08-11T06:37:25Z", "EventCode": "1",
        "CommandLine": "powershell iwr hxxp://evil[.]example.com/a.ps1 -o x; curl 203.0.113.9; python tool.py 10.0.0.2",
    })
    iocs = extract_iocs(ev)
    assert "evil.example.com" in iocs
    assert "203.0.113.9" in iocs
    assert "10.0.0.2" not in iocs
    assert "tool.py" not in iocs


def test_benign_domain_filter_is_applied_but_ips_remain(splunk_rows):
    ev = to_canonical(splunk_rows["22"][0])
    iocs = extract_iocs(ev, is_benign_domain=lambda d: d.endswith("githubusercontent.com"))
    assert "raw.githubusercontent.com" not in iocs
    assert "185.199.109.133" in iocs


def test_sha256_preferred_over_md5():
    ev = to_canonical({"_time": "2026-08-11T06:37:25Z", "EventCode": "1",
                       "Hashes": "MD5=" + "a" * 32 + ",SHA256=" + "b" * 64})
    assert extract_iocs(ev) == ["b" * 64]
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_ioc.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

Create `backend/app/normalization/ioc.py`:

```python
"""The single IOC extractor. Replaces the duplicate logic in ingestion and the context agent."""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Literal

import tldextract

from app.normalization.canonical import CanonicalEvent

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled snapshot, no network

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.I)
_URL_HOST_RE = re.compile(r"(?:https?|hxxps?)://([^/\s\"'<>?#]+)", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]+$")
# Real ccTLD/gTLDs that overwhelmingly appear as file extensions inside command lines.
_FILE_LIKE_TLDS = {"py", "sh", "zip", "mov", "pl", "rs", "md", "cc", "ps", "so"}


def defang(text: str) -> str:
    return (text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
                .replace("hxxp", "http").replace("hXXp", "http"))


def public_ip(value: str | None) -> str | None:
    """Return the normalized IP only when it is globally routable (not private/reserved/multicast)."""
    if not value:
        return None
    text = value.strip()
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(ip) if ip.is_global and not ip.is_multicast else None


def public_domain(value: str | None, allow_file_tlds: bool = False) -> str | None:
    """Return a lowercase domain only if it has a real public suffix (so 'wpad', '*.local', 'calc.exe' fail)."""
    if not value:
        return None
    text = value.strip().lower().rstrip(".")
    if not text or "/" in text or " " in text:
        return None
    parts = _EXTRACT(text)
    if not parts.suffix or not parts.domain:
        return None
    if not allow_file_tlds and parts.suffix in _FILE_LIKE_TLDS:
        return None
    return text


def ioc_kind(ioc: str) -> Literal["ip", "domain", "hash"]:
    if public_ip(ioc) or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ioc):
        return "ip"
    if _HEX_RE.match(ioc) and len(ioc) in (32, 40, 64):
        return "hash"
    return "domain"


def _text_iocs(text: str | None, benign) -> list[str]:
    if not text:
        return []
    text = defang(text)
    found: list[str] = []
    for match in _URL_HOST_RE.finditer(text):
        host = match.group(1).split(":")[0]
        candidate = public_ip(host) or public_domain(host, allow_file_tlds=True)
        if candidate:
            found.append(candidate)
    for match in _IPV4_RE.finditer(text):
        ip = public_ip(match.group(0))
        if ip:
            found.append(ip)
    for match in _DOMAIN_RE.finditer(text):
        domain = public_domain(match.group(0))
        if domain:
            found.append(domain)
    return found


def extract_iocs(
    event: CanonicalEvent,
    is_benign_domain: Callable[[str], bool] | None = None,
) -> list[str]:
    """Ordered, deduplicated indicators: public IPs, public domains, one hash (sha256 preferred)."""
    candidates: list[str] = []
    for ip in (event.dst_ip, event.src_ip):
        ip = public_ip(ip)
        if ip:
            candidates.append(ip)

    dns = public_domain(event.query_name, allow_file_tlds=True)
    if dns:
        candidates.append(dns)
    for part in (event.query_results or "").split(";"):
        ip = public_ip(part.strip())
        if ip:
            candidates.append(ip)

    for algo in ("sha256", "sha1", "md5"):
        if event.hashes.get(algo):
            candidates.append(event.hashes[algo])
            break

    candidates += _text_iocs(event.command_line, is_benign_domain)
    candidates += _text_iocs(event.script_block, is_benign_domain)

    seen: set[str] = set()
    result: list[str] = []
    for item in candidates:
        key = item.lower()
        if key in seen:
            continue
        if ioc_kind(key) == "domain" and is_benign_domain and is_benign_domain(key):
            continue
        seen.add(key)
        result.append(key)
    return result
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_ioc.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/normalization/ioc.py backend/tests/test_norm_ioc.py
git commit -m "feat(normalization): add unified IOC extractor with public-suffix and ipaddress checks"
```

---

### Task 5: Noise suppression

**Files:**
- Create: `backend/config/noise.yaml`, `backend/app/normalization/noise.py`
- Test: `backend/tests/test_norm_noise.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces: `class NoiseFilter` with `NoiseFilter.from_yaml(path: str | Path) -> NoiseFilter`, `NoiseFilter.from_dict(cfg: dict) -> NoiseFilter`, `is_benign_domain(domain: str) -> bool`, `reason(event: CanonicalEvent) -> str | None` (the suppression rule name, or None to keep).

Condition keys in `suppress[].where` (all given conditions must hold): `subject_user_endswith: str`, `domain_benign: true`, `process_in: [str]` (lowercase basenames), `parent_in: [str]`, `command_line_regex: str`.

- [ ] **Step 1: Write the policy file**

Create `backend/config/noise.yaml`:

```yaml
# Noise suppression policy. Everything suppressed is counted per rule in
# ingestion_runs.suppressed, so the policy is auditable. Keep entries narrow.

# Registered domains whose subdomains are never worth a threat-intel lookup
# or a DNS detection. Do not add file-hosting or paste domains here.
benign_domains:
  - microsoft.com
  - windowsupdate.com
  - windows.com
  - msftconnecttest.com
  - office.com
  - office365.com
  - live.com
  - digicert.com
  - symcd.com

suppress:
  # Machine accounts (NAME$) making explicit-credential logons is routine
  # service behavior (service SIDs, virtual machine accounts).
  - name: machine_account_explicit_logon
    event_code: "4648"
    where:
      subject_user_endswith: "$"

  - name: benign_dns_lookup
    event_code: "22"
    where:
      domain_benign: true

  # Telemetry shipping from the lab Splunk forwarder.
  - name: splunk_forwarder_traffic
    event_code: "3"
    where:
      process_in: [splunkd.exe, splunk-winevtlog.exe]
```

- [ ] **Step 2: Write the failing tests**

Create `backend/tests/test_norm_noise.py`:

```python
from app.core.config import settings
from app.normalization.mappers import to_canonical
from app.normalization.noise import NoiseFilter


def _filter():
    return NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH)


def test_real_machine_account_4648_rows_are_suppressed(splunk_rows):
    noise = _filter()
    ev = to_canonical(splunk_rows["4648"][0])
    assert noise.reason(ev) == "machine_account_explicit_logon"


def test_suspicious_dns_domain_is_not_suppressed(splunk_rows):
    noise = _filter()
    ev = to_canonical(splunk_rows["22"][0])  # raw.githubusercontent.com must stay visible
    assert noise.reason(ev) is None


def test_benign_domain_matches_subdomains_only_at_label_boundary():
    noise = _filter()
    assert noise.is_benign_domain("v10.events.data.microsoft.com")
    assert noise.is_benign_domain("microsoft.com")
    assert not noise.is_benign_domain("notmicrosoft.com")
    assert not noise.is_benign_domain("microsoft.com.evil.io")


def test_benign_dns_event_suppressed():
    noise = _filter()
    ev = to_canonical({"_time": "2026-08-11T06:37:25Z", "EventCode": "22", "QueryName": "settings-win.data.microsoft.com"})
    assert noise.reason(ev) == "benign_dns_lookup"


def test_where_conditions_are_all_required():
    noise = NoiseFilter.from_dict({"suppress": [{
        "name": "x", "event_code": "1",
        "where": {"process_in": ["a.exe"], "command_line_regex": "^safe"},
    }]})
    base = {"_time": "2026-08-11T06:37:25Z", "EventCode": "1", "Image": "C:\\a.exe"}
    assert noise.reason(to_canonical({**base, "CommandLine": "safe run"})) == "x"
    assert noise.reason(to_canonical({**base, "CommandLine": "evil run"})) is None
```

- [ ] **Step 3: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_noise.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 4: Implement**

Create `backend/app/normalization/noise.py`:

```python
"""Data-driven noise suppression. Policy lives in config/noise.yaml."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from app.normalization.canonical import CanonicalEvent


class NoiseFilter:
    def __init__(self, benign_domains: list[str], rules: list[dict]) -> None:
        self.benign_domains = tuple(d.lower().rstrip(".") for d in benign_domains)
        self.rules = rules

    @classmethod
    def from_dict(cls, cfg: dict) -> "NoiseFilter":
        return cls(cfg.get("benign_domains") or [], cfg.get("suppress") or [])

    @classmethod
    def from_yaml(cls, path: str | Path) -> "NoiseFilter":
        p = Path(path)
        if not p.is_absolute() and not p.exists():
            p = Path(__file__).resolve().parents[2] / p  # relative paths resolve from backend/ when cwd differs
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)

    def is_benign_domain(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        return any(d == b or d.endswith("." + b) for b in self.benign_domains)

    def _matches(self, rule: dict, ev: CanonicalEvent) -> bool:
        if rule.get("event_code") and str(rule["event_code"]) != ev.event_code:
            return False
        where = rule.get("where") or {}
        if "subject_user_endswith" in where and not (ev.subject_user or "").endswith(where["subject_user_endswith"]):
            return False
        if where.get("domain_benign") and not (ev.query_name and self.is_benign_domain(ev.query_name)):
            return False
        if "process_in" in where and (ev.process or "") not in [p.lower() for p in where["process_in"]]:
            return False
        if "parent_in" in where and (ev.parent or "") not in [p.lower() for p in where["parent_in"]]:
            return False
        if "command_line_regex" in where and not re.search(where["command_line_regex"], ev.command_line or ""):
            return False
        return True

    def reason(self, event: CanonicalEvent) -> str | None:
        """Name of the first matching suppression rule, or None to keep the event."""
        for rule in self.rules:
            if self._matches(rule, event):
                return rule["name"]
        return None
```

- [ ] **Step 5: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_noise.py -q`
Expected: all PASS (tests run from `backend/`, so the relative `config/noise.yaml` path resolves).

- [ ] **Step 6: Commit**

```bash
git add backend/config/noise.yaml backend/app/normalization/noise.py backend/tests/test_norm_noise.py
git commit -m "feat(normalization): add data-driven noise suppression policy"
```

---

### Task 6: Deduplication, stable IDs and failed-logon aggregation

**Files:**
- Create: `backend/app/normalization/dedup.py`
- Test: `backend/tests/test_norm_dedup.py`

**Interfaces:**
- Consumes: `CanonicalEvent`; rules are any object with a `.name: str` attribute (the existing `DetectionRule`).
- Produces (`app.normalization.dedup`):
  - `@dataclass class RuleHit: rule: Any; event: CanonicalEvent; count: int = 1`
  - `@dataclass class AlertGroup: alert_id: str; rule: Any; first: CanonicalEvent; count: int; first_seen: datetime; last_seen: datetime; events: list[CanonicalEvent]` (events capped at 50)
  - `stable_id(*parts: object) -> str` (32 hex chars)
  - `group_hits(hits: Iterable[RuleHit], org_id: str, bucket_seconds: int) -> list[AlertGroup]`
  - `aggregate_failed_logons(events: Iterable[CanonicalEvent], threshold: int, bucket_seconds: int) -> list[tuple[CanonicalEvent, int]]` returns one representative event and the failure count for each `(source, host, bucket)` that reaches `threshold`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_norm_dedup.py`:

```python
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.normalization.canonical import CanonicalEvent
from app.normalization.dedup import RuleHit, aggregate_failed_logons, group_hits, stable_id

RULE = SimpleNamespace(name="r1")
T0 = datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc)


def ev(i: int, **kw) -> CanonicalEvent:
    base = dict(event_id=f"e{i}", ts=T0 + timedelta(seconds=i), event_code="22", host_key="h1",
                user="u", query_name="a.example.com")
    base.update(kw)
    return CanonicalEvent(**base)


def test_stable_id_deterministic_and_sensitive():
    assert stable_id("a", 1) == stable_id("a", 1)
    assert stable_id("a", 1) != stable_id("a", 2)
    assert len(stable_id("x")) == 32


def test_repeated_events_collapse_into_one_alert_with_count():
    hits = [RuleHit(RULE, ev(i)) for i in range(5)]
    groups = group_hits(hits, org_id="default", bucket_seconds=300)
    assert len(groups) == 1
    g = groups[0]
    assert g.count == 5
    assert g.first_seen == T0 and g.last_seen == T0 + timedelta(seconds=4)


def test_different_entities_do_not_collapse():
    hits = [RuleHit(RULE, ev(0, query_name="a.example.com")), RuleHit(RULE, ev(1, query_name="b.example.com"))]
    assert len(group_hits(hits, "default", 300)) == 2


def test_group_ids_are_stable_across_runs_and_orgs_differ():
    hits = [RuleHit(RULE, ev(0))]
    assert group_hits(hits, "default", 300)[0].alert_id == group_hits(hits, "default", 300)[0].alert_id
    assert group_hits(hits, "default", 300)[0].alert_id != group_hits(hits, "acme", 300)[0].alert_id


def test_different_rules_on_same_event_make_separate_alerts():
    r2 = SimpleNamespace(name="r2")
    hits = [RuleHit(RULE, ev(0)), RuleHit(r2, ev(0))]
    assert len({g.alert_id for g in group_hits(hits, "default", 300)}) == 2


def test_distinct_brute_force_sources_get_distinct_ids():
    """Regression: every brute-force alert used to hash to the same ID."""
    fails = [ev(i, event_code="4625", src_ip="203.0.113.5", target_user="admin") for i in range(6)]
    fails += [ev(i + 10, event_code="4625", src_ip="198.51.100.7", target_user="admin") for i in range(7)]
    agg = aggregate_failed_logons(fails, threshold=5, bucket_seconds=300)
    groups = group_hits([RuleHit(RULE, e, c) for e, c in agg], "default", 300)
    assert sorted(g.count for g in groups) == [6, 7]
    assert len({g.alert_id for g in groups}) == 2


def test_aggregate_failed_logons_threshold_and_buckets():
    under = [ev(i, event_code="4625", src_ip="203.0.113.5") for i in range(4)]
    assert aggregate_failed_logons(under, threshold=5, bucket_seconds=300) == []
    spread = [ev(i * 400, event_code="4625", src_ip="203.0.113.5") for i in range(6)]  # one per bucket
    assert aggregate_failed_logons(spread, threshold=5, bucket_seconds=300) == []
    ok = [ev(i, event_code="4625", src_ip="203.0.113.5") for i in range(5)]
    (rep, count), = aggregate_failed_logons(ok, threshold=5, bucket_seconds=300)
    assert count == 5 and rep.event_id == "e0"


def test_aggregate_ignores_non_4625_events():
    mixed = [ev(i, event_code="22") for i in range(10)]
    assert aggregate_failed_logons(mixed, threshold=5, bucket_seconds=300) == []
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_dedup.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

Create `backend/app/normalization/dedup.py`:

```python
"""Collapse repeated detections into one alert and derive stable IDs."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from app.normalization.canonical import CanonicalEvent

MAX_GROUP_EVENTS = 50


@dataclass
class RuleHit:
    rule: Any
    event: CanonicalEvent
    count: int = 1


@dataclass
class AlertGroup:
    alert_id: str
    rule: Any
    first: CanonicalEvent
    count: int
    first_seen: datetime
    last_seen: datetime
    events: list[CanonicalEvent] = field(default_factory=list)


def stable_id(*parts: object) -> str:
    material = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _bucket(ts: datetime, bucket_seconds: int) -> int:
    return int(ts.timestamp()) // bucket_seconds


def _entity_key(ev: CanonicalEvent) -> tuple:
    """Fields that define 'the same detection' for each event type."""
    code = ev.event_code
    if code in ("1", "4688"):
        return (ev.process, ev.command_line)
    if code == "3":
        return (ev.process, ev.dst_ip, ev.dst_port)
    if code == "13":
        return (ev.registry_key,)
    if code == "22":
        return (ev.process, ev.query_name)
    if code == "4104":
        return (hashlib.sha256((ev.script_block or "").encode()).hexdigest(),)
    if code == "4648":
        return (ev.subject_user, ev.target_user)
    if code == "4625":
        return (ev.src_ip or ev.workstation, ev.target_user)
    return (ev.event_id,)


def group_hits(hits: Iterable[RuleHit], org_id: str, bucket_seconds: int) -> list[AlertGroup]:
    groups: dict[str, AlertGroup] = {}
    for hit in hits:
        ev = hit.event
        bucket = _bucket(ev.ts, bucket_seconds)
        alert_id = stable_id(org_id, hit.rule.name, ev.host_key, ev.user, bucket, *_entity_key(ev))
        group = groups.get(alert_id)
        if group is None:
            groups[alert_id] = AlertGroup(
                alert_id=alert_id, rule=hit.rule, first=ev, count=hit.count,
                first_seen=ev.ts, last_seen=ev.ts, events=[ev],
            )
            continue
        group.count += hit.count
        if ev.ts < group.first_seen:
            group.first_seen, group.first = ev.ts, ev
        group.last_seen = max(group.last_seen, ev.ts)
        if len(group.events) < MAX_GROUP_EVENTS:
            group.events.append(ev)
    return list(groups.values())


def aggregate_failed_logons(
    events: Iterable[CanonicalEvent], threshold: int, bucket_seconds: int,
) -> list[tuple[CanonicalEvent, int]]:
    """One (representative event, failure count) per (source, host, bucket) with count >= threshold."""
    buckets: dict[tuple, list[CanonicalEvent]] = defaultdict(list)
    for ev in events:
        if ev.event_code != "4625":
            continue
        source = ev.src_ip or ev.workstation or "unknown"
        buckets[(source, ev.host_key, _bucket(ev.ts, bucket_seconds))].append(ev)
    result = []
    for items in buckets.values():
        if len(items) >= threshold:
            items.sort(key=lambda e: e.ts)
            result.append((items[0], len(items)))
    return result
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_dedup.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/normalization/dedup.py backend/tests/test_norm_dedup.py
git commit -m "feat(normalization): add dedup grouping, stable IDs and failed-logon aggregation"
```

---

### Task 7: Alert document builder

**Files:**
- Create: `backend/app/normalization/alerts.py`
- Test: `backend/tests/test_norm_alerts.py`

**Interfaces:**
- Consumes: `AlertGroup` (Task 6), `NoiseFilter` (Task 5), `extract_iocs` (Task 4), existing `DetectionRule` fields (`name`, `description`, `severity`, `alert_type`, `mitre_technique`, `mitre_tactic`).
- Produces: `build_alert_doc(group: AlertGroup, org_id: str, noise: NoiseFilter | None = None) -> dict` with `_id`, all legacy fields from Global Constraints, plus `count`, `first_seen`, `last_seen`, `event_ids` (list), `raw_events` (up to 20), `cleaning_notes`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_norm_alerts.py`:

```python
from datetime import datetime, timedelta, timezone

from app.models.alert import AlertModel
from app.normalization.alerts import build_alert_doc
from app.normalization.canonical import CanonicalEvent
from app.normalization.dedup import RuleHit, group_hits
from app.normalization.mappers import to_canonical
from app.services.detection_rules import DetectionRuleEngine


def _rule(name):
    return next(r for r in DetectionRuleEngine().get_all_rules() if r.name == name)


def _doc_for_matching_rule(row):
    ev = to_canonical(row)
    rule = next(r for r in DetectionRuleEngine().get_all_rules() if r.match_fn and r.match_fn(ev.fields))
    group = group_hits([RuleHit(rule, ev)], "default", 300)[0]
    return build_alert_doc(group, "default"), ev, rule


def test_real_dns_row_builds_legacy_compatible_doc(splunk_rows):
    doc, ev, rule = _doc_for_matching_rule(splunk_rows["22"][0])
    assert doc["_id"] and len(doc["_id"]) == 32
    assert doc["rule_name"] == rule.name and doc["severity"] == rule.severity
    assert doc["dns_query"] == "raw.githubusercontent.com"
    assert doc["created_at"] == ev.ts
    assert doc["status"] == "New" and doc["ai_confidence"] == 0
    assert doc["org_id"] == "default" and doc["source_siem"] == "splunk"
    assert doc["raw_event"] == splunk_rows["22"][0]
    assert doc["count"] == 1 and doc["event_ids"] == [ev.event_id]
    assert "185.199.109.133" in doc["extracted_iocs"]
    AlertModel(**doc)  # the existing API model must still accept the document


def test_real_registry_row_keeps_process_and_key(splunk_rows):
    doc, _, rule = _doc_for_matching_rule(splunk_rows["13"][0])
    assert rule.name == "registry_run_key_persistence" or "run" in rule.name
    assert doc["process_name"] == "chrome.exe"
    assert "currentversion\run" in doc["registry_key"].lower()


def test_grouped_alert_reports_count_and_window():
    t0 = datetime(2026, 8, 11, 6, 0, tzinfo=timezone.utc)
    events = [CanonicalEvent(event_id=f"e{i}", ts=t0 + timedelta(seconds=i), event_code="4625",
                             host="LAB", host_key="lab", src_ip="203.0.113.5", target_user="admin", user="admin")
              for i in range(6)]
    group = group_hits([RuleHit(_rule("brute_force_login"), events[0], 6)], "default", 300)[0]
    doc = build_alert_doc(group, "default")
    assert doc["count"] == 6
    assert "6 failures from 203.0.113.5" in doc["title"]
    assert doc["source_ip"] == "203.0.113.5"
    assert "203.0.113.5" in doc["extracted_iocs"]
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_alerts.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

Create `backend/app/normalization/alerts.py`:

```python
"""Build the stored alert document from a deduplicated AlertGroup."""

from __future__ import annotations

from datetime import datetime, timezone

from app.normalization.dedup import AlertGroup
from app.normalization.ioc import extract_iocs
from app.normalization.noise import NoiseFilter

MAX_RAW_EVENTS = 20


def _title(group: AlertGroup) -> str:
    rule, ev = group.rule, group.first
    tag = f"[{rule.severity.upper()}]"
    host = ev.host or "Unknown"
    code = ev.event_code
    if code == "1":
        return f"{tag} {rule.alert_type} – {ev.process or '?'} on {host}"
    if code == "3":
        return f"{tag} {rule.alert_type} – {ev.dst_ip or '?'}:{ev.dst_port or '?'} from {host}"
    if code == "13":
        key = (ev.registry_key or "").split("\\")[-1]
        return f"{tag} {rule.alert_type} – {key} on {host}"
    if code == "22":
        return f"{tag} {rule.alert_type} – {ev.query_name or '?'} on {host}"
    if code == "4625":
        return f"{tag} {rule.alert_type} – {group.count} failures from {ev.src_ip or ev.workstation or '?'}"
    if code == "4648":
        return f"{tag} {rule.alert_type} – {ev.subject_user or '?'} → {ev.target_user or '?'}"
    if code == "4688":
        return f"{tag} {rule.alert_type} – {ev.parent or '?'} → {ev.process or '?'} on {host}"
    if code == "4104":
        return f"{tag} {rule.alert_type} – Script Block on {host}"
    return f"{tag} {rule.alert_type} on {host}"


def build_alert_doc(group: AlertGroup, org_id: str, noise: NoiseFilter | None = None) -> dict:
    ev, rule = group.first, group.rule
    benign = noise.is_benign_domain if noise else None

    iocs: list[str] = []
    for event in group.events:
        for ioc in extract_iocs(event, is_benign_domain=benign):
            if ioc not in iocs:
                iocs.append(ioc)

    notes: list[str] = []
    for event in group.events:
        for note in event.cleaning_notes:
            if note not in notes:
                notes.append(note)

    return {
        "_id": group.alert_id,
        "org_id": org_id,
        "title": _title(group),
        "description": rule.description,
        "severity": rule.severity,
        "alert_type": rule.alert_type,
        "rule_name": rule.name,
        "mitre_technique": rule.mitre_technique,
        "mitre_tactic": rule.mitre_tactic,
        "host": ev.host or "Unknown",
        "user": ev.user_display or ev.user or "Unknown",
        "status": "New",
        "ai_confidence": 0,
        "source_siem": "splunk",
        "event_code": ev.event_code,
        "created_at": group.first_seen,
        "first_seen": group.first_seen,
        "last_seen": group.last_seen,
        "count": group.count,
        "detected_at": datetime.now(timezone.utc),
        "extracted_iocs": iocs,
        "process_name": ev.process_path.split("\\")[-1] if ev.process_path else None,
        "command_line": ev.command_line or ev.script_block,
        "parent_process": ev.parent_path.split("\\")[-1] if ev.parent_path else None,
        "source_ip": ev.src_ip,
        "dest_ip": ev.dst_ip,
        "dest_port": str(ev.dst_port) if ev.dst_port is not None else None,
        "protocol": ev.protocol,
        "registry_key": ev.registry_key,
        "registry_details": ev.registry_details,
        "dns_query": ev.query_name,
        "hashes": ev.fields.get("Hashes"),
        "logon_type": ev.logon_type,
        "failure_reason": ev.failure_reason,
        "event_ids": [e.event_id for e in group.events],
        "raw_event": ev.raw,
        "raw_events": [e.raw for e in group.events[:MAX_RAW_EVENTS]],
        "cleaning_notes": notes,
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_norm_alerts.py -q`
Expected: all PASS. (The brute-force rule's own `match_fn` is bypassed by aggregation, so the grouped test constructs its hit directly. If the registry rule name differs, print `[r.name for r in DetectionRuleEngine().get_all_rules()]` and fix the assertion to the real name.)

- [ ] **Step 5: Commit**

```bash
git add backend/app/normalization/alerts.py backend/tests/test_norm_alerts.py
git commit -m "feat(normalization): add alert document builder with legacy-compatible fields"
```

---

### Task 8: Paginated Splunk reads

**Files:**
- Modify: `backend/app/infrastructure/siem/splunk.py` (add method after `get_results`)
- Test: `backend/tests/test_splunk_pages.py`

**Interfaces:**
- Produces: `async def SplunkClient.search_raw_pages(self, query: str, earliest_time: str, latest_time: str = "now", page_size: int = 500, max_pages: int = 20) -> AsyncIterator[list[dict]]` yielding raw result rows; stops on an empty or short page or after `max_pages`.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_splunk_pages.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_splunk_pages.py -q`
Expected: FAIL (`AttributeError: ... search_raw_pages`).

- [ ] **Step 3: Implement**

In `backend/app/infrastructure/siem/splunk.py`, add `AsyncIterator` to the typing import (`from typing import List, Dict, Any, Optional, AsyncIterator`) and add this method directly after `get_results`:

```python
    async def search_raw_pages(
        self,
        query: str,
        earliest_time: str,
        latest_time: str = "now",
        page_size: int = 500,
        max_pages: int = 20,
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Runs one search job and yields raw result rows page by page (no normalization)."""
        clean_query = query.strip()
        if not (clean_query.startswith("search") or clean_query.startswith("|")):
            clean_query = f"search {clean_query}"

        sid = await self.submit_search(clean_query, earliest_time, latest_time)
        await self.poll_search(sid, max_wait_seconds=120)

        for page_index in range(max_pages):
            rows = await self.get_results(sid, offset=page_index * page_size, limit=page_size)
            if not rows:
                return
            yield rows
            if len(rows) < page_size:
                return
```

- [ ] **Step 4: Run to verify pass and no regressions**

Run: `./venv/Scripts/python.exe -m pytest tests/test_splunk_pages.py tests/test_splunk_client.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/infrastructure/siem/splunk.py backend/tests/test_splunk_pages.py
git commit -m "feat(splunk): add paginated raw search generator"
```

---

### Task 9: Ingestion rewrite

**Files:**
- Modify (rewrite): `backend/app/services/ingestion.py`
- Test: `backend/tests/test_ingestion_service.py`

**Interfaces:**
- Consumes: Tasks 2–8 (`to_canonical`, `NoiseFilter`, `RuleHit`, `group_hits`, `aggregate_failed_logons`, `build_alert_doc`, `SplunkClient.search_raw_pages`), existing `DetectionRuleEngine().get_all_rules()` (rules expose `.name`, `.match_fn`, `.event_codes`).
- Produces: `IngestionService(db, org_id: str = "default", splunk_factory=SplunkClient, noise: NoiseFilter | None = None)` with `async fetch_and_store_alerts(self, limit: int | None = None) -> list[dict]` (new alert docs). Attributes after a run: `errors: list[dict]`, `total_fetched: int`, `rules_run: int`. Collections written: `alerts` (upsert), `ingestion_state` (`_id = f"cursor:{org_id}:splunk"`, field `ts` ISO of newest processed event; also keeps legacy `_id="last_ingested"` ISO `ts` updated for the dashboard), `ingestion_runs`. Module constants: `BRUTE_FORCE_RULE = "brute_force_login"`.
- The existing `/alerts/ingest` endpoint and poller call `IngestionService(db[, org])` and `.fetch_and_store_alerts()`; those call sites keep working. The `limit` argument is accepted and ignored (paging is configured via settings).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_ingestion_service.py`:

```python
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

    rows = [row(i, "203.0.113.5") for i in range(6)] + [row(i, "198.51.100.7") for i in range(5)] + [row(0, "192.0.2.9")]
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
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_ingestion_service.py -q`
Expected: FAIL (old `IngestionService` has no `splunk_factory`/`noise` parameters).

- [ ] **Step 3: Implement**

Replace the entire contents of `backend/app/services/ingestion.py` with:

```python
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

    async def _load_cursor(self) -> Optional[datetime]:
        for doc_id in (self._cursor_id, "last_ingested"):  # legacy doc keeps existing installs from re-ingesting
            doc = await self.db[self.STATE_COLLECTION].find_one({"_id": doc_id})
            if doc and doc.get("ts"):
                parsed = parse_ts(doc["ts"])
                if parsed:
                    return parsed
        return None

    async def _save_cursor(self, newest: Optional[datetime]) -> None:
        if newest is None:
            return
        iso = newest.isoformat()
        await self.db[self.STATE_COLLECTION].update_one({"_id": self._cursor_id}, {"$set": {"ts": iso}}, upsert=True)
        await self.db[self.STATE_COLLECTION].update_one({"_id": "last_ingested"}, {"$set": {"ts": iso}}, upsert=True)

    def _earliest_epoch(self, cursor: Optional[datetime]) -> str:
        if cursor is None:
            start = datetime.now(timezone.utc) - timedelta(hours=settings.INGEST_INITIAL_LOOKBACK_HOURS)
        else:
            start = cursor - timedelta(seconds=settings.INGEST_OVERLAP_SECONDS)
        return str(int(start.timestamp()))

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

    async def _store(self, groups, run: dict) -> List[dict]:
        new_alerts: List[dict] = []
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
            cursor = await self._load_cursor()
            events, newest = await self._collect(splunk, self._earliest_epoch(cursor), run)
            stage = "detect"
            hits = self._detect(events, run)
            run["hits"] = len(hits)
            stage = "store"
            groups = group_hits(hits, self.org_id, settings.INGEST_DEDUP_BUCKET_SECONDS)
            new_alerts = await self._store(groups, run)
            await self._save_cursor(newest)  # only reached when every stage succeeded
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
```

- [ ] **Step 4: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_ingestion_service.py -q`
Expected: all PASS. If `$max` on a datetime fails under mongomock, store `last_seen` via `$max` only after the first insert by switching to `$set` of `last_seen` when greater (adjust `_store` and keep the test). Do not weaken the idempotency assertion.

- [ ] **Step 5: Run the whole suite**

Run: `./venv/Scripts/python.exe -m pytest -q`
Expected: all previously passing tests plus new ones PASS (57 + new).

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/ingestion.py backend/tests/test_ingestion_service.py
git commit -m "feat(ingestion): cursor, pagination, idempotent upserts, noise and dedup pipeline"
```

---

### Task 10: Single-poller lease and poller cleanup

**Files:**
- Create: `backend/app/services/lease.py`
- Modify: `backend/app/services/poller.py`
- Test: `backend/tests/test_lease_poller.py`

**Interfaces:**
- Produces: `async acquire_lease(db, name: str, owner: str, ttl_seconds: int) -> bool`; `async release_lease(db, name: str, owner: str) -> None`.
- Produces: `AlertPoller.owner: str`, `async AlertPoller._run_cycle(self) -> int` (returns number of new alerts; 0 and no ingestion when the lease is held elsewhere).
- Behavior: new `IngestionService` per cycle (counters no longer accumulate), investigation tasks are retained in `self._tasks` and bounded by `asyncio.Semaphore(settings.INVESTIGATION_CONCURRENCY)`, `org_id` is set via the service default (`"default"`).

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_lease_poller.py`:

```python
from unittest.mock import AsyncMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.lease import acquire_lease, release_lease
from app.services.poller import AlertPoller


@pytest.fixture
def db():
    return AsyncMongoMockClient()["lease_test"]


@pytest.mark.asyncio
async def test_only_one_owner_holds_the_lease(db):
    assert await acquire_lease(db, "poller", "a", 60)
    assert not await acquire_lease(db, "poller", "b", 60)
    assert await acquire_lease(db, "poller", "a", 60)  # owner can renew


@pytest.mark.asyncio
async def test_expired_lease_can_be_taken_over(db):
    assert await acquire_lease(db, "poller", "a", -1)  # already expired
    assert await acquire_lease(db, "poller", "b", 60)
    assert not await acquire_lease(db, "poller", "a", 60)


@pytest.mark.asyncio
async def test_release_frees_the_lease(db):
    await acquire_lease(db, "poller", "a", 60)
    await release_lease(db, "poller", "a")
    assert await acquire_lease(db, "poller", "b", 60)
    await release_lease(db, "poller", "a")  # non-owner release is a no-op
    assert not await acquire_lease(db, "poller", "a", 60)


@pytest.mark.asyncio
async def test_cycle_skips_ingestion_when_lease_is_held_elsewhere(db):
    await acquire_lease(db, "alert_poller", "someone-else", 60)
    poller = AlertPoller(db, interval_seconds=30)
    with patch("app.services.poller.IngestionService") as svc:
        assert await poller._run_cycle() == 0
        svc.assert_not_called()


@pytest.mark.asyncio
async def test_cycle_uses_a_fresh_service_each_time_and_schedules_investigations(db):
    poller = AlertPoller(db, interval_seconds=30)
    created = []

    def make_service(*a, **k):
        inst = AsyncMock()
        inst.fetch_and_store_alerts.return_value = [{"_id": f"a{len(created)}", "rule_name": "r"}]
        created.append(inst)
        return inst

    poller._investigate_alert = AsyncMock()
    with patch("app.services.poller.IngestionService", side_effect=make_service):
        assert await poller._run_cycle() == 1
        assert await poller._run_cycle() == 1
    import asyncio
    await asyncio.gather(*list(poller._tasks))
    assert len(created) == 2
    assert poller._investigate_alert.await_count == 2
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_lease_poller.py -q`
Expected: FAIL (`ModuleNotFoundError: app.services.lease`).

- [ ] **Step 3: Implement the lease**

Create `backend/app/services/lease.py`:

```python
"""Tiny Mongo-backed lease so only one process runs the alert poller."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError


def _now() -> datetime:
    # Mongo returns naive UTC datetimes, so keep stored and compared values naive UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def acquire_lease(db, name: str, owner: str, ttl_seconds: int) -> bool:
    """True if `owner` now holds the lease (new, renewed, or taken over after expiry)."""
    now = _now()
    try:
        doc = await db["leases"].find_one_and_update(
            {"_id": name, "$or": [{"owner": owner}, {"expires_at": {"$lte": now}}]},
            {"$set": {"owner": owner, "expires_at": now + timedelta(seconds=ttl_seconds)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
    except DuplicateKeyError:  # another owner holds an unexpired lease
        return False
    return bool(doc and doc.get("owner") == owner)


async def release_lease(db, name: str, owner: str) -> None:
    await db["leases"].delete_one({"_id": name, "owner": owner})
```

- [ ] **Step 4: Rework the poller**

In `backend/app/services/poller.py`: replace the imports block and the `AlertPoller.__init__`, `_poll_loop`, and `stop` pieces as follows, leaving `_investigate_alert` unchanged (stage 3 replaces it).

Replace everything above `async def _investigate_alert` with:

```python
import asyncio
import uuid

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.agents.graph import investigation_graph
from app.core.config import settings
from app.core.logging import logger
from app.services.ingestion import IngestionService
from app.services.lease import acquire_lease, release_lease

LEASE_NAME = "alert_poller"


class AlertPoller:
    def __init__(self, db: AsyncIOMotorDatabase, interval_seconds: int = 30):
        self.db = db
        self.interval_seconds = interval_seconds
        self.owner = str(uuid.uuid4())
        self._running = False
        self._task = None
        self._tasks: set = set()
        self._semaphore = asyncio.Semaphore(settings.INVESTIGATION_CONCURRENCY)

    async def _run_cycle(self) -> int:
        """One poll: take/renew the lease, ingest, schedule bounded auto-investigations."""
        if not await acquire_lease(self.db, LEASE_NAME, self.owner, settings.POLLER_LEASE_TTL_SECONDS):
            logger.info("poller_lease_held_elsewhere")
            return 0

        service = IngestionService(self.db)  # fresh per cycle: counters and errors do not accumulate
        new_alerts = await service.fetch_and_store_alerts()
        if not new_alerts:
            logger.info("poller_no_new_alerts")
            return 0

        logger.info("poller_new_alerts", count=len(new_alerts), rules=sorted({a.get("rule_name") for a in new_alerts}))
        for alert in new_alerts:
            task = asyncio.create_task(self._bounded_investigation(alert))
            self._tasks.add(task)  # keep a reference so the task is not garbage-collected
            task.add_done_callback(self._tasks.discard)
        return len(new_alerts)

    async def _bounded_investigation(self, alert: dict) -> None:
        async with self._semaphore:
            await self._investigate_alert(alert)

    async def _poll_loop(self):
        while self._running:
            try:
                await self._run_cycle()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("alert_poller_error", error=str(e))

            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                break

```

Replace the `stop` method at the bottom with:

```python
    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        try:
            asyncio.get_running_loop().create_task(release_lease(self.db, LEASE_NAME, self.owner))
        except RuntimeError:
            pass  # no running loop at interpreter shutdown; the lease simply expires
        logger.info("alert_poller_stopped")
```

(Keep `start` unchanged.)

- [ ] **Step 5: Run to verify pass**

Run: `./venv/Scripts/python.exe -m pytest tests/test_lease_poller.py tests/test_main_lifespan.py -q`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/lease.py backend/app/services/poller.py backend/tests/test_lease_poller.py
git commit -m "feat(poller): single-poller lease, fresh service per cycle, bounded investigations"
```

---

### Task 11: Indexes, ingestion health endpoint, context-agent IOC cleanup, docs

**Files:**
- Create: `backend/app/database/indexes.py`, `backend/tests/test_indexes_health.py`
- Modify: `backend/app/main.py`, `backend/app/api/v1/endpoints/dashboard.py`, `backend/app/agents/context_agent.py`, `README.md`

**Interfaces:**
- Produces: `async ensure_indexes(db) -> None` creating: `alerts`: `(org_id, created_at desc)`, `host_key`-independent lookups `host`, `user`, `extracted_iocs`, `status`; `ingestion_runs`: `(org_id, started_at desc)` plus TTL on `started_at` (30 days); `leases`: none.
- Produces: `GET /api/v1/dashboard/ingestion-health` returning `{"last_run": {...}|None, "runs": [... up to 20 newest ...], "totals": {"fetched": int, "suppressed": int, "alerts_new": int}}` scoped to the caller's tenant.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_indexes_health.py`:

```python
from datetime import datetime, timedelta, timezone

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.agents.context_agent import extract_context_node
from app.api.v1.endpoints.dashboard import ingestion_health
from app.database.indexes import ensure_indexes


@pytest.mark.asyncio
async def test_ensure_indexes_creates_expected_indexes():
    db = AsyncMongoMockClient()["idx"]
    await ensure_indexes(db)
    alert_idx = await db["alerts"].index_information()
    assert any("extracted_iocs" in name for name in alert_idx)
    assert any("org_id" in name and "created_at" in name for name in alert_idx)
    runs_idx = await db["ingestion_runs"].index_information()
    assert any(v.get("expireAfterSeconds") for v in runs_idx.values())


@pytest.mark.asyncio
async def test_ingestion_health_is_tenant_scoped_and_aggregates():
    db = AsyncMongoMockClient()["health"]
    now = datetime.now(timezone.utc)
    await db["ingestion_runs"].insert_many([
        {"_id": "r1", "org_id": "default", "started_at": now - timedelta(minutes=2), "status": "ok",
         "fetched": 10, "suppressed": {"a": 3, "b": 1}, "alerts_new": 2},
        {"_id": "r2", "org_id": "default", "started_at": now, "status": "error",
         "fetched": 0, "suppressed": {}, "alerts_new": 0, "errors": [{"stage": "fetch", "error": "down"}]},
        {"_id": "r3", "org_id": "other", "started_at": now, "status": "ok", "fetched": 99, "suppressed": {}, "alerts_new": 9},
    ])
    body = await ingestion_health(db=db, user={"org_id": "default"})
    assert body["last_run"]["_id"] == "r2" and body["last_run"]["status"] == "error"
    assert [r["_id"] for r in body["runs"]] == ["r2", "r1"]
    assert body["totals"] == {"fetched": 10, "suppressed": 4, "alerts_new": 2}


def test_context_agent_uses_global_ip_check(splunk_rows):
    row = dict(splunk_rows["3"][0])
    state = {"alert_data": {"_id": "x", "raw_event": row, "extracted_iocs": []}, "investigation_log": []}
    iocs = extract_context_node(state)["extracted_iocs"]
    assert "34.206.0.173" in iocs
    assert not any(i.startswith(("10.", "192.168.", "172.16.", "169.254.")) for i in iocs)
```

- [ ] **Step 2: Run to verify failure**

Run: `./venv/Scripts/python.exe -m pytest tests/test_indexes_health.py -q`
Expected: FAIL (`ModuleNotFoundError: app.database.indexes`).

- [ ] **Step 3: Implement indexes**

Create `backend/app/database/indexes.py`:

```python
"""MongoDB index definitions, created idempotently at startup."""

from __future__ import annotations

RUNS_TTL_SECONDS = 30 * 24 * 3600


async def ensure_indexes(db) -> None:
    alerts = db["alerts"]
    await alerts.create_index([("org_id", 1), ("created_at", -1)])
    await alerts.create_index("host")
    await alerts.create_index("user")
    await alerts.create_index("extracted_iocs")
    await alerts.create_index("status")

    runs = db["ingestion_runs"]
    await runs.create_index([("org_id", 1), ("started_at", -1)])
    await runs.create_index("started_at", expireAfterSeconds=RUNS_TTL_SECONDS)
```

- [ ] **Step 4: Wire it into startup**

In `backend/app/main.py` add `from app.database.indexes import ensure_indexes` next to the other imports, and inside `lifespan`, immediately after the `ioc_cache` TTL index block (still inside `if db_config.client:`), add:

```python
        await ensure_indexes(db)
```

- [ ] **Step 5: Add the health endpoint**

Append to `backend/app/api/v1/endpoints/dashboard.py`:

```python
@router.get("/ingestion-health")
async def ingestion_health(db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Recent ingestion cycles for the caller's tenant: counts, suppression, errors and lag."""
    runs = []
    cursor = db["ingestion_runs"].find(scoped_query(user)).sort("started_at", -1).limit(20)
    async for run in cursor:
        for key in ("started_at", "finished_at"):
            if hasattr(run.get(key), "isoformat"):
                run[key] = run[key].isoformat()
        runs.append(run)
    totals = {
        "fetched": sum(r.get("fetched", 0) for r in runs),
        "suppressed": sum(sum((r.get("suppressed") or {}).values()) for r in runs),
        "alerts_new": sum(r.get("alerts_new", 0) for r in runs),
    }
    return {"last_run": runs[0] if runs else None, "runs": runs, "totals": totals}
```

- [ ] **Step 6: Switch the context agent to the shared IP check**

In `backend/app/agents/context_agent.py`, add `from app.normalization.ioc import public_ip` to the imports, and replace the block starting at `# Re-extract just in case` through the `for i in list(ips) + list(domains):` loop (the `is_valid_ioc` helper and its loop) with:

```python
    # Re-extract just in case, using the shared global-address check
    for candidate in (raw.get("SourceIp"), raw.get("DestinationIp"), raw.get("IpAddress")):
        ip = public_ip(candidate)
        if ip:
            existing_iocs.add(ip)
    query_name = raw.get("QueryName")
    if isinstance(query_name, str) and query_name.strip() not in ("", "-"):
        from app.normalization.ioc import public_domain
        domain = public_domain(query_name, allow_file_tlds=True)
        if domain:
            existing_iocs.add(domain)
```

- [ ] **Step 7: Run to verify pass, then the whole suite**

Run: `./venv/Scripts/python.exe -m pytest tests/test_indexes_health.py -q` then `./venv/Scripts/python.exe -m pytest -q`
Expected: all PASS; no previously passing test fails.

- [ ] **Step 8: Document**

Add a section "Ingestion pipeline" to `README.md` (backend part) covering: the flow raw row → `CanonicalEvent` → noise → rules → dedup → upsert; `config/noise.yaml` policy and that suppression is counted; the new settings from Task 1; the `GET /api/v1/dashboard/ingestion-health` endpoint; regenerating fixtures with `scripts/export_fixture_rows.py`.

- [ ] **Step 9: Commit**

```bash
git add backend/app/database/indexes.py backend/app/main.py backend/app/api/v1/endpoints/dashboard.py backend/app/agents/context_agent.py backend/tests/test_indexes_health.py README.md
git commit -m "feat: indexes, ingestion-health endpoint, shared IOC checks, ingestion docs"
```

---

### Task 12: Live verification against real Splunk

**Files:** none created; this is a verification gate before stage 2.

- [ ] **Step 1: Run one real cycle**

With Splunk, Mongo and the `.env` configured, from `backend/`:

```bash
./venv/Scripts/python.exe - <<'EOF'
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from app.services.ingestion import IngestionService

async def main():
    db = AsyncIOMotorClient(settings.MONGO_URI)[settings.MONGO_DB_NAME]
    svc = IngestionService(db)
    new = await svc.fetch_and_store_alerts()
    run = await db["ingestion_runs"].find_one(sort=[("started_at", -1)])
    print({k: run[k] for k in ("status", "fetched", "unmapped", "suppressed", "hits", "alerts_new", "alerts_seen", "truncated", "lag_seconds", "errors")})

asyncio.run(main())
EOF
```

Expected: `status: ok`, `fetched > 0`, a non-empty `suppressed` map (the machine-account 4648 noise), and `alerts_new` far lower than `fetched`.

- [ ] **Step 2: Confirm the brute-force regression is fixed**

Run a handful of failed logons from different source addresses (or use existing 4625 data), run another cycle and confirm distinct `brute_force_login` alerts exist per source:

```bash
./venv/Scripts/python.exe -c "
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
async def m():
    db = AsyncIOMotorClient(settings.MONGO_URI)[settings.MONGO_DB_NAME]
    async for a in db['alerts'].find({'rule_name':'brute_force_login'},{'title':1,'count':1,'source_ip':1}): print(a)
asyncio.run(m())"
```

- [ ] **Step 3: Record results**

Note the numbers (fetched, suppressed, alerts) in the stage 2 plan as the noise-reduction starting point, then merge `feat/stage1-data-layer` after review.
