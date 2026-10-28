"""
Unit tests for SplunkClient normalization and event conversion logic.
"""

import pytest
from app.infrastructure.siem.splunk import SplunkClient
from app.schemas.normalized_event import NormalizedEvent


def test_normalize_splunk_event():
    """Test converting raw Splunk JSON into NormalizedEvent model."""
    client = SplunkClient()
    raw_event = {
        "_time": "2026-08-06T14:30:00Z",
        "EventCode": "1",
        "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
        "host": "AYUSH-VICTUS",
        "user": "AYUSH\\ayush",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand QW50aWdyYXZpdHk=",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ProcessId": "4128",
    }

    normalized: NormalizedEvent = client._normalize_splunk_event(raw_event)

    assert normalized.event_id == "1"
    assert normalized.hostname == "AYUSH-VICTUS"
    assert normalized.user == "AYUSH\\ayush"
    assert normalized.process_name == "C:\\Windows\\System32\\powershell.exe"
    assert normalized.command_line == "powershell.exe -EncodedCommand QW50aWdyYXZpdHk="
    assert normalized.process_id == 4128
    assert normalized.parent_process_name == "C:\\Windows\\explorer.exe"
