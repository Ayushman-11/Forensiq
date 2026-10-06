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
    base = {"_time": "2026-08-11T06:37:25Z", "EventCode": "1", "Image": "C:\\a.exe"}
    assert noise.reason(to_canonical({**base, "CommandLine": "safe run"})) == "x"
    assert noise.reason(to_canonical({**base, "CommandLine": "evil run"})) is None
