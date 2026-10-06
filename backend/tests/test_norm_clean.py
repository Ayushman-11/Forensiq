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
