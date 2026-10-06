"""
Exports a few real Splunk rows per EventCode from the committed lab dump into
tests/fixtures/splunk_rows.json. The dump stores each alert's original row as
`raw_event` (underscore-prefixed Splunk keys were stripped), so `_time` is
restored from the alert's created_at.

Personal identifiers are pseudonymized; the source dump stays local and untracked.

Usage (from backend/): ./venv/Scripts/python.exe scripts/export_fixture_rows.py
"""

import json
import re
from pathlib import Path

DUMP = Path("mongo_dump_json/alerts.json")
OUT = Path("tests/fixtures/splunk_rows.json")
PER_CODE = 3


def _iso(value) -> str:
    if isinstance(value, dict):
        value = value.get("$date")
    return str(value)


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+")
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])(?:10\." + _OCT + r"\." + _OCT + r"\." + _OCT
    + r"|172\.(?:1[6-9]|2\d|3[01])\." + _OCT + r"\." + _OCT
    + r"|192\.168\." + _OCT + r"\." + _OCT + r")(?!\d|\.\d)"
)
_NAME_RE = re.compile(r"ayush[a-z0-9]*", re.I)


def _case_like(match: "re.Match[str]") -> str:
    word = match.group(0)
    if word.isupper():
        return "LABUSER"
    if word[0].isupper():
        return "Labuser"
    return "labuser"


def pseudonymize(text: str) -> str:
    """Replace personal identifiers from the lab machine with neutral stand-ins (applied before fixtures are written)."""
    text = _EMAIL_RE.sub("analyst@example.test", text)
    text = _SID_RE.sub("S-1-5-21-1000000000-2000000000-3000000000", text)
    text = _PRIVATE_IP_RE.sub("10.0.0.5", text)
    return _NAME_RE.sub(_case_like, text)


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
    OUT.write_text(pseudonymize(json.dumps(rows, indent=2, ensure_ascii=False)), encoding="utf-8")
    print({code: len(items) for code, items in rows.items()})


if __name__ == "__main__":
    main()
