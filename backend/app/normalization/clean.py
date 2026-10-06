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
