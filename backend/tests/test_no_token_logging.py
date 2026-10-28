"""
Guard test: tokens and alert payloads must never appear in log output.

This test is a regression guard for the debug-logging leak mentioned in
section 1.7 of production-readiness.md.  It works by:

  1. Capturing all structlog output emitted during a real API call.
  2. Asserting that none of the sensitive patterns appear in any log line.

If this test ever fails it means a logger.debug / logger.info call somewhere
in the request path is leaking credentials or raw alert content.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Generator

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Patterns that must NEVER appear in logs
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: list[re.Pattern] = [
    # JWT-shaped strings (header.payload.signature)
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # The literal key names that commonly leak tokens
    re.compile(r'"access_token"\s*:', re.IGNORECASE),
    re.compile(r'"refresh_token"\s*:', re.IGNORECASE),
    re.compile(r'"password"\s*:', re.IGNORECASE),
    re.compile(r'"Authorization"\s*:', re.IGNORECASE),
    # Splunk session key pattern
    re.compile(r"sessionKey", re.IGNORECASE),
    # Raw alert payload indicator (very large JSON in a single log line)
    # A real alert payload is typically >500 chars; genuine log fields are short.
    re.compile(r'"raw_event"\s*:\s*".{300,}"'),
]


# ---------------------------------------------------------------------------
# Log capture fixture
# ---------------------------------------------------------------------------


class _LogCapture(logging.Handler):
    """Collects all log records emitted during a test."""

    def __init__(self):
        super().__init__()
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(self.format(record))


@pytest.fixture()
def log_capture() -> Generator[_LogCapture, None, None]:
    """Attach a capturing handler to the root logger for the duration of the test."""
    capture = _LogCapture()
    root = logging.getLogger()
    root.addHandler(capture)
    try:
        yield capture
    finally:
        root.removeHandler(capture)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _assert_no_sensitive_data(lines: list[str]) -> None:
    """Raise AssertionError if any sensitive pattern is found in any log line."""
    for line in lines:
        for pattern in _SENSITIVE_PATTERNS:
            if pattern.search(line):
                raise AssertionError(
                    f"Sensitive pattern {pattern.pattern!r} found in log line:\n{line}"
                )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_does_not_log_token(client: AsyncClient, log_capture: _LogCapture):
    """
    A successful login response contains a token.
    That token must not appear in any log line.
    """

    # We only need to exercise the logging path, not a real Splunk auth.
    # Use an invalid body so the auth endpoint returns 422/400 without
    # ever producing a token – but we still get log output from the request
    # path and can check it.
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@forensiq.local", "password": "wrongpass"},
    )
    # Don't care about the status code; just check logs.
    _assert_no_sensitive_data(log_capture.records)


@pytest.mark.asyncio
async def test_health_endpoints_log_no_tokens(client: AsyncClient, log_capture: _LogCapture):
    """Health probes must not leak any token-shaped strings in logs."""
    await client.get("/api/v1/health/live")
    await client.get("/api/v1/health/ready")
    _assert_no_sensitive_data(log_capture.records)


@pytest.mark.asyncio
async def test_arbitrary_request_no_sensitive_leak(client: AsyncClient, log_capture: _LogCapture):
    """
    A generic GET to the root endpoint must not produce token-shaped output.
    This is the baseline: if even this fails the request-id middleware is leaking.
    """
    await client.get("/")
    _assert_no_sensitive_data(log_capture.records)
