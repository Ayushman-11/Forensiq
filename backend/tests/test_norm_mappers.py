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


def test_list_valued_fields_map_to_same_event_as_scalar_row(splunk_rows):
    original = splunk_rows["3"][0]
    row = dict(original)
    row["EventData_Xml"] = [original["EventData_Xml"]]          # single-item list
    row["host"] = [original["host"], original["host"]]          # multi-item list
    row["DestinationPort"] = [original["DestinationPort"]]
    expected = to_canonical(original)
    got = to_canonical(row)
    assert got is not None
    assert got.model_dump(exclude={"raw", "event_id"}) == expected.model_dump(exclude={"raw", "event_id"})


def test_list_valued_xml_blob_split_in_pieces(splunk_rows):
    import re
    original = splunk_rows["3"][0]
    pieces = re.findall(r"<Data .*?</Data>", original["EventData_Xml"], re.S)
    assert len(pieces) > 1
    row = dict(original, EventData_Xml=pieces)
    expected = to_canonical(original)
    got = to_canonical(row)
    assert got is not None
    assert (got.dst_ip, got.dst_port, got.process) == (expected.dst_ip, expected.dst_port, expected.process)


def test_forwarder_row_with_list_event_data_and_repeated_channel_does_not_raise():
    row = {
        "_time": "2026-08-11T13:45:59.860Z",
        "EventCode": "1",
        "sourcetype": "XmlWinEventLog",
        "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "host": "Labuser",
        "Event.System.Channel": ["Microsoft-Windows-Sysmon/Operational"] * 3,
        "Event.EventData.Data": ["Usermode", "2026-08-11 13:45:57.500", "{ff454333-4068}"],
        "EventData_Xml": ["<Data Name='RuleName'>Usermode</Data>"],
    }
    ev = to_canonical(row)
    assert ev is not None
    assert ev.event_code == "1"
    assert ev.process is None
