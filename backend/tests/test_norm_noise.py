from app.core.config import settings
from app.normalization.mappers import to_canonical
from app.normalization.noise import NoiseFilter


def _filter():
    return NoiseFilter.from_yaml(settings.NOISE_CONFIG_PATH)


def test_real_machine_account_4648_rows_are_suppressed(splunk_rows):
    noise = _filter()
    ev = to_canonical(splunk_rows["4648"][0])
    assert noise.reason(ev) == "machine_account_explicit_logon"


def test_suspicious_dns_domain_is_not_suppressed(splunk_rows):
    noise = _filter()
    ev = to_canonical(splunk_rows["22"][0])  # raw.githubusercontent.com must stay visible
    assert noise.reason(ev) is None


def test_benign_domain_matches_subdomains_only_at_label_boundary():
    noise = _filter()
    assert noise.is_benign_domain("v10.events.data.microsoft.com")
    assert noise.is_benign_domain("microsoft.com")
    assert not noise.is_benign_domain("notmicrosoft.com")
    assert not noise.is_benign_domain("microsoft.com.evil.io")


def test_benign_dns_event_suppressed():
    noise = _filter()
    ev = to_canonical({"_time": "2026-08-11T06:37:25Z", "EventCode": "22", "QueryName": "settings-win.data.microsoft.com"})
    assert noise.reason(ev) == "benign_dns_lookup"


def test_where_conditions_are_all_required():
    noise = NoiseFilter.from_dict({"suppress": [{
        "name": "x", "event_code": "1",
        "where": {"process_in": ["a.exe"], "command_line_regex": "^safe"},
    }]})
    base = {"_time": "2026-08-11T06:37:25Z", "EventCode": "1", "Image": r"C:\\a.exe"}
    assert noise.reason(to_canonical({**base, "CommandLine": "safe run"})) == "x"
    assert noise.reason(to_canonical({**base, "CommandLine": "evil run"})) is None


_FWD = {"_time": "2026-08-11T06:37:25Z", "EventCode": "3", "DestinationIp": "8.8.8.8"}


def test_forwarder_in_install_path_is_suppressed():
    noise = _filter()
    ev = to_canonical({**_FWD, "Image": r"C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe"})
    assert noise.reason(ev) == "splunk_forwarder_traffic"


def test_forwarder_basename_outside_install_path_is_not_suppressed():
    noise = _filter()
    ev = to_canonical({**_FWD, "Image": r"C:\Users\x\Temp\splunkd.exe"})
    assert noise.reason(ev) is None


def test_process_path_startswith_is_case_insensitive():
    noise = NoiseFilter.from_dict({"suppress": [{
        "name": "p", "event_code": "3",
        "where": {"process_path_startswith": [r"C:\Program Files\Splunk" "\\"]},
    }]})
    ev = to_canonical({**_FWD, "Image": r"c:\program files\SPLUNK\bin\splunkd.exe"})
    assert noise.reason(ev) == "p"


import pytest

_EV = {"_time": "2026-08-11T06:37:25Z", "EventCode": "4648"}


def test_unknown_where_key_raises_naming_rule_and_key():
    with pytest.raises(ValueError, match=r"r1.*procss_in"):
        NoiseFilter.from_dict({"suppress": [{"name": "r1", "event_code": "3", "where": {"procss_in": ["a.exe"]}}]})


def test_empty_where_raises():
    with pytest.raises(ValueError, match="r2"):
        NoiseFilter.from_dict({"suppress": [{"name": "r2", "event_code": "3", "where": {}}]})
    with pytest.raises(ValueError, match="r2"):
        NoiseFilter.from_dict({"suppress": [{"name": "r2", "event_code": "3"}]})


def test_missing_name_raises():
    with pytest.raises(ValueError, match="name"):
        NoiseFilter.from_dict({"suppress": [{"event_code": "3", "where": {"process_in": ["a.exe"]}}]})


def test_bad_regex_raises_at_load():
    with pytest.raises(ValueError, match="command_line_regex"):
        NoiseFilter.from_dict({"suppress": [{"name": "r3", "where": {"command_line_regex": "("}}]})
    with pytest.raises(ValueError, match="fields_regex"):
        NoiseFilter.from_dict({"suppress": [{"name": "r4", "where": {"fields_regex": {"A": "("}}}]})


def test_shipped_config_loads():
    assert _filter().rules


def test_all_real_4648_rows_are_suppressed(splunk_rows):
    noise = _filter()
    assert len(splunk_rows["4648"]) == 3
    for row in splunk_rows["4648"]:
        assert noise.reason(to_canonical(row)) == "machine_account_explicit_logon"


def _4648(**over):
    xml = ("<Data Name='SubjectUserName'>{subj}</Data><Data Name='TargetServerName'>{srv}</Data>"
           "<Data Name='ProcessName'>{proc}</Data>").format(
        subj=over.get("subj", "AYUSH$"), srv=over.get("srv", "localhost"),
        proc=over.get("proc", r"C:\Windows\System32\lsass.exe"))
    return to_canonical({**_EV, "SubjectUserName": over.get("subj", "AYUSH$"), "EventData_Xml": xml})


def test_machine_account_rule_baseline_suppresses():
    assert _filter().reason(_4648()) == "machine_account_explicit_logon"


def test_dollar_user_running_from_temp_is_not_suppressed():
    ev = _4648(subj="x$", proc=r"C:\Users\x\Temp\evil.exe")
    assert _filter().reason(ev) is None


def test_system32_lsass_to_remote_server_is_not_suppressed():
    assert _filter().reason(_4648(srv="fileserver01")) is None
