def test_fixture_has_real_rows_for_each_supported_event_code(splunk_rows):
    for code in ("1", "3", "13", "22", "4104", "4648"):
        assert splunk_rows[code], f"no fixture rows for EventCode {code}"
        assert splunk_rows[code][0]["EventCode"] == code
        assert splunk_rows[code][0]["_time"]
