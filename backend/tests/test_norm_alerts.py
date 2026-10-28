from datetime import datetime, timedelta, timezone

from app.models.alert import AlertModel
from app.normalization.alerts import build_alert_doc
from app.normalization.canonical import CanonicalEvent
from app.normalization.dedup import RuleHit, group_hits
from app.normalization.mappers import to_canonical
from app.services.detection_rules import DetectionRuleEngine


def _rule(name):
    return next(r for r in DetectionRuleEngine().get_all_rules() if r.name == name)


def _doc_for_matching_rule(row):
    ev = to_canonical(row)
    rule = next(r for r in DetectionRuleEngine().get_all_rules() if r.match_fn and r.match_fn(ev.fields))
    group = group_hits([RuleHit(rule, ev)], "default", 300)[0]
    return build_alert_doc(group, "default"), ev, rule


def test_real_dns_row_builds_legacy_compatible_doc(splunk_rows):
    doc, ev, rule = _doc_for_matching_rule(splunk_rows["22"][0])
    assert doc["_id"] and len(doc["_id"]) == 32
    assert doc["rule_name"] == rule.name and doc["severity"] == rule.severity
    assert doc["dns_query"] == "raw.githubusercontent.com"
    assert doc["created_at"] == ev.ts
    assert doc["status"] == "New" and doc["ai_confidence"] == 0
    assert doc["org_id"] == "default" and doc["source_siem"] == "splunk"
    assert doc["raw_event"] == splunk_rows["22"][0]
    assert doc["count"] == 1 and doc["event_ids"] == [ev.event_id]
    assert "185.199.109.133" in doc["extracted_iocs"]
    AlertModel(**doc)  # the existing API model must still accept the document


def test_real_registry_row_keeps_process_and_key(splunk_rows):
    doc, _, rule = _doc_for_matching_rule(splunk_rows["13"][0])
    assert rule.name == "registry_run_key_persistence" or "run" in rule.name
    assert doc["process_name"] == "chrome.exe"
    assert "currentversion\\run" in doc["registry_key"].lower()


def test_grouped_alert_reports_count_and_window():
    t0 = datetime(2026, 8, 11, 6, 0, tzinfo=timezone.utc)
    events = [CanonicalEvent(event_id=f"e{i}", ts=t0 + timedelta(seconds=i), event_code="4625",
                             host="LAB", host_key="lab", src_ip="45.33.32.156", target_user="admin", user="admin")
              for i in range(6)]
    group = group_hits([RuleHit(_rule("brute_force_login"), events[0], 6)], "default", 300)[0]
    doc = build_alert_doc(group, "default")
    assert doc["count"] == 6
    assert "6 failures from 45.33.32.156" in doc["title"]
    assert doc["source_ip"] == "45.33.32.156"
    assert "45.33.32.156" in doc["extracted_iocs"]
