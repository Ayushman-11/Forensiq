from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.normalization.canonical import CanonicalEvent
from app.normalization.dedup import RuleHit, aggregate_failed_logons, group_hits, stable_id

RULE = SimpleNamespace(name="r1")
T0 = datetime(2026, 8, 11, 6, 0, 0, tzinfo=timezone.utc)


def ev(i: int, **kw) -> CanonicalEvent:
    base = dict(event_id=f"e{i}", ts=T0 + timedelta(seconds=i), event_code="22", host_key="h1",
                user="u", query_name="a.example.com")
    base.update(kw)
    return CanonicalEvent(**base)


def test_stable_id_deterministic_and_sensitive():
    assert stable_id("a", 1) == stable_id("a", 1)
    assert stable_id("a", 1) != stable_id("a", 2)
    assert len(stable_id("x")) == 32


def test_repeated_events_collapse_into_one_alert_with_count():
    hits = [RuleHit(RULE, ev(i)) for i in range(5)]
    groups = group_hits(hits, org_id="default", bucket_seconds=300)
    assert len(groups) == 1
    g = groups[0]
    assert g.count == 5
    assert g.first_seen == T0 and g.last_seen == T0 + timedelta(seconds=4)


def test_different_entities_do_not_collapse():
    hits = [RuleHit(RULE, ev(0, query_name="a.example.com")), RuleHit(RULE, ev(1, query_name="b.example.com"))]
    assert len(group_hits(hits, "default", 300)) == 2


def test_group_ids_are_stable_across_runs_and_orgs_differ():
    hits = [RuleHit(RULE, ev(0))]
    assert group_hits(hits, "default", 300)[0].alert_id == group_hits(hits, "default", 300)[0].alert_id
    assert group_hits(hits, "default", 300)[0].alert_id != group_hits(hits, "acme", 300)[0].alert_id


def test_different_rules_on_same_event_make_separate_alerts():
    r2 = SimpleNamespace(name="r2")
    hits = [RuleHit(RULE, ev(0)), RuleHit(r2, ev(0))]
    assert len({g.alert_id for g in group_hits(hits, "default", 300)}) == 2


def test_distinct_brute_force_sources_get_distinct_ids():
    """Regression: every brute-force alert used to hash to the same ID."""
    fails = [ev(i, event_code="4625", src_ip="45.33.32.156", target_user="admin") for i in range(6)]
    fails += [ev(i + 10, event_code="4625", src_ip="185.220.101.4", target_user="admin") for i in range(7)]
    agg = aggregate_failed_logons(fails, threshold=5, bucket_seconds=300)
    groups = group_hits([RuleHit(RULE, e, c) for e, c in agg], "default", 300)
    assert sorted(g.count for g in groups) == [6, 7]
    assert len({g.alert_id for g in groups}) == 2


def test_aggregate_failed_logons_threshold_and_buckets():
    under = [ev(i, event_code="4625", src_ip="45.33.32.156") for i in range(4)]
    assert aggregate_failed_logons(under, threshold=5, bucket_seconds=300) == []
    spread = [ev(i * 400, event_code="4625", src_ip="45.33.32.156") for i in range(6)]  # one per bucket
    assert aggregate_failed_logons(spread, threshold=5, bucket_seconds=300) == []
    ok = [ev(i, event_code="4625", src_ip="45.33.32.156") for i in range(5)]
    (rep, count), = aggregate_failed_logons(ok, threshold=5, bucket_seconds=300)
    assert count == 5 and rep.event_id == "e0"


def test_aggregate_ignores_non_4625_events():
    mixed = [ev(i, event_code="22") for i in range(10)]
    assert aggregate_failed_logons(mixed, threshold=5, bucket_seconds=300) == []
