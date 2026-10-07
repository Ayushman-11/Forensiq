import pytest

from app.services import detection_rules
from app.services.detection_rules import _external_network


def _row(dest_ip, port="4444"):
    return {
        "EventCode": "3",
        "Initiated": "true",
        "DestinationIp": dest_ip,
        "DestinationPort": port,
    }


@pytest.mark.parametrize("ip", [
    "::1",
    "0:0:0:0:0:0:0:1",
    "fe80::1",
    "fe80:0:0:0:6167:9038:1edc:47d4",
    "fd00::1",
    "::ffff:10.0.0.1",
    "10.1.2.3",
    "172.20.0.5",
    "192.168.1.9",
    "127.0.0.1",
    "169.254.10.10",
    "100.64.0.1",
    "224.0.0.251",
    "ff02::fb",
    "ff02:0:0:0:0:0:0:fb",
])
def test_internal_destinations_are_not_external(ip):
    assert _external_network(_row(ip)) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700::1111", "185.199.109.133"])
def test_public_destinations_are_external(ip):
    assert _external_network(_row(ip)) is True


@pytest.mark.parametrize("port", ["389", "445"])
def test_live_false_positive_shapes_no_longer_fire(port):
    assert _external_network(_row("0:0:0:0:0:0:0:1", port)) is False
    assert _external_network(_row("fe80:0:0:0:6167:9038:1edc:47d4", port)) is False


def test_standard_ports_and_missing_ip_still_ignored():
    assert _external_network(_row("8.8.8.8", "443")) is False
    assert _external_network(_row("")) is False
    assert _external_network(_row("not-an-ip")) is False


def test_rule_names_unchanged():
    names = [r.name for r in detection_rules._RULES]
    assert names == [
        "brute_force_login",
        "suspicious_powershell_execution",
        "registry_run_key_persistence",
        "suspicious_external_connection",
        "dns_suspicious_query",
        "powershell_script_block_logging",
        "lateral_movement_explicit_credentials",
        "process_creation_anomaly",
    ]
