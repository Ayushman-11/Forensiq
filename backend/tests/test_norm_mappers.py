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
