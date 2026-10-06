"""Allowlist-based guard for user-supplied SPL. Rejects anything that is not a plain search + safe pipeline."""

from __future__ import annotations

import re
from typing import Iterable

ALLOWED_COMMANDS = frozenset(
    {"search", "where", "table", "stats", "eval", "fields", "sort", "head", "tail", "top", "rare", "dedup", "spath", "rex"}
)
MAX_QUERY_CHARS = 4000
MAX_PIPELINE_STAGES = 10

_QUOTED_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_INDEX_RE = re.compile(r'\bindex\s*(!=|=)\s*"?([^\s")|,]+)', re.I)
_INDEX_IN_RE = re.compile(r"\bindex\s+in\b", re.I)
_TIME_MODIFIER_RE = re.compile(r"\b(?:earliest|latest|_index_earliest|_index_latest)\s*=", re.I)
_SEARCH_PREFIX_RE = re.compile(r"(?is)^search(?:\s+(.*))?$")
_COMMAND_RE = re.compile(r"^([A-Za-z_]+)(?=\s|$)")
_REL_TIME_RE = re.compile(r"^-(\d+)(s|m|h|d|w)$")
_BOOLEAN_RE = re.compile(r"\b(?:OR|NOT)\b", re.I)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class SPLRejected(ValueError):
    """The query or time range is not allowed. The message is safe to return to the caller."""


def _split_pipeline(query: str) -> list[str]:
    """Split on `|` outside double quotes; reject subsearch brackets, macro backticks and backslashes outside quotes."""
    segments: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for ch in query:
        if in_quote:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            continue
        if ch == '"':
            in_quote = True
            current.append(ch)
        elif ch == "\\":
            # Splunk treats an escaped quote/pipe outside quotes as a literal, which desyncs this scanner.
            raise SPLRejected("Backslashes are only allowed inside quoted strings")
        elif ch in "[]`":
            raise SPLRejected("Subsearches and macros are not allowed")
        elif ch == "|":
            segments.append("".join(current))
            current = []
        else:
            current.append(ch)
    if in_quote:
        raise SPLRejected("Unterminated quote in query")
    segments.append("".join(current))
    return segments


def validate_search(query: str, *, allowed_indexes: Iterable[str], default_index: str) -> str:
    if any(ord(c) < 32 and c not in "\t\n\r" for c in (query or "")):
        raise SPLRejected("Query contains control characters")
    text = (query or "").strip()
    if not text:
        raise SPLRejected("Query must not be empty")
    if len(text) > MAX_QUERY_CHARS:
        raise SPLRejected(f"Query is longer than {MAX_QUERY_CHARS} characters")

    segments = _split_pipeline(text)
    if len(segments) > MAX_PIPELINE_STAGES:
        raise SPLRejected(f"Query has more than {MAX_PIPELINE_STAGES} pipeline stages")

    first = segments[0].strip()
    if not first:
        raise SPLRejected("Query must start with a search expression, not a command")
    prefix = _SEARCH_PREFIX_RE.match(first)
    body = (prefix.group(1) or "") if prefix else first

    for stage in segments[1:]:
        match = _COMMAND_RE.match(stage.strip())
        if not match:
            raise SPLRejected("Empty or malformed pipeline stage")
        if match.group(1).lower() not in ALLOWED_COMMANDS:
            raise SPLRejected(f"Command '{match.group(1).lower()}' is not allowed")

    for part in [body, *segments[1:]]:
        blanked = _QUOTED_RE.sub('""', part)
        if "\\(" in blanked or "\\)" in blanked:
            raise SPLRejected("Escaped parentheses are not allowed")
        depth = 0
        for ch in blanked:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    break
        if depth != 0:
            raise SPLRejected("Unbalanced parentheses in query")

    allowed = {i.lower() for i in allowed_indexes}
    for part in [body, *segments[1:]]:
        if _TIME_MODIFIER_RE.search(_QUOTED_RE.sub('""', part)):
            raise SPLRejected("Inline earliest/latest modifiers are not allowed; use the time range fields")
        if _INDEX_IN_RE.search(part):
            raise SPLRejected("index IN (...) is not allowed")
        for operator, value in _INDEX_RE.findall(part):
            if operator == "!=":
                raise SPLRejected("index!= is not allowed")
            if value.lower() not in allowed:
                raise SPLRejected(f"Index '{value}' is not allowed")

    unq_body = _QUOTED_RE.sub('""', body)
    if _BOOLEAN_RE.search(unq_body) or "(" in unq_body or ")" in unq_body:
        body = f"index={default_index} ({body.strip()})"
    else:
        body = f"index={default_index} {body.strip()}".strip()
    return " | ".join(["search " + body.strip(), *[s.strip() for s in segments[1:]]])


def _seconds(value: str, allow_now: bool) -> int:
    v = (value or "").strip()
    if allow_now and v == "now":
        return 0
    match = _REL_TIME_RE.match(v)
    if not match:
        raise SPLRejected(f"Unsupported time value '{v}'; use relative values such as -15m, -24h or -7d")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def validate_time_range(earliest: str, latest: str, max_days: int) -> None:
    start = _seconds(earliest, allow_now=False)
    end = _seconds(latest, allow_now=True)
    if start > max_days * 86400:
        raise SPLRejected(f"Time range exceeds {max_days} days")
    if start <= end:
        raise SPLRejected("earliest_time must be before latest_time")
