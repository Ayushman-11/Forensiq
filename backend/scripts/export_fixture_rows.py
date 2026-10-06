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
