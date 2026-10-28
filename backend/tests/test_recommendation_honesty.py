"""
Recommendations must not overstate threat-intel evidence (audit 2026-10-28, P0-2 / P0-3).
"""

from app.agents.recommendation_agent import _deterministic_recommendation


def _vt(ioc, ioc_type, reputation="malicious", status="ok"):
    return {"ioc": ioc, "ioc_type": ioc_type, "reputation": reputation, "source": "VirusTotal", "status": status}


def _abuse(ioc, reputation="malicious"):
    return {"ioc": ioc, "ioc_type": "ip", "reputation": reputation, "source": "AbuseIPDB", "status": "ok"}


def _steps(rec):
    return " ".join(rec["checklist"]) + " " + rec["recommendation"]


def test_single_source_verdict_is_never_called_confirmed():
    rec = _deterministic_recommendation(
        {"host": "h1"}, [_vt("203.0.113.9", "ip")], [], [], {"risk_score": 70},
    )
    text = _steps(rec)
    assert "confirmed" not in text.lower()
    assert "Validate ip '203.0.113.9'" in text
    assert rec["containment_required"] is False


def test_two_agreeing_sources_are_confirmed_and_contained():
    rec = _deterministic_recommendation(
        {"host": "h1"}, [_vt("203.0.113.9", "ip"), _abuse("203.0.113.9")], [], [], {"risk_score": 90},
    )
    assert "Block confirmed malicious ip '203.0.113.9' (corroborated by AbuseIPDB, VirusTotal)" in _steps(rec)
    assert rec["containment_required"] is True


def test_shared_hosting_domain_is_never_blocked_wholesale():
    rec = _deterministic_recommendation(
        {"host": "h1"},
        [_vt("raw.githubusercontent.com", "domain"), {**_vt("raw.githubusercontent.com", "domain"), "source": "OtherFeed"}],
        [], [], {"risk_score": 90},
    )
    text = _steps(rec)
    assert "do not block the domain" in text
    assert "Block confirmed malicious domain 'raw.githubusercontent.com'" not in text


def test_unavailable_feed_results_are_not_evidence():
    rec = _deterministic_recommendation(
        {"host": "h1"}, [_vt("203.0.113.9", "ip", status="error")], [], [], {"risk_score": 40},
    )
    assert "203.0.113.9" not in _steps(rec)


def test_credential_dumping_gets_containment_and_credential_reset():
    rec = _deterministic_recommendation(
        {"host": "attackdata", "user": "CORP\\Administrator"}, [], [],
        [{"technique": "T1003.001"}, {"technique": "T1059.001"}], {"risk_score": 100},
    )
    text = _steps(rec)
    assert rec["containment_required"] is True
    assert "Reset passwords" in text
    assert "authorized IT administrative tasks" not in text


def test_peer_hosts_exclude_the_alert_host():
    rec = _deterministic_recommendation(
        {"host": "h1"},
        [_vt("203.0.113.9", "ip"), _abuse("203.0.113.9")],
        [{"host": "h1"}, {"host": "h2"}],
        [], {"risk_score": 95},
    )
    assert "(h2)" in rec["checklist"][0]
    assert "h1, " not in rec["checklist"][0]
