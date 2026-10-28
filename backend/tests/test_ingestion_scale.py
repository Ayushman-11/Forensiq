import pytest
import time
from scripts.benchmark_ingestion_100x import (
    generate_100x_telemetry,
    simulate_spl_prefilter,
    evaluate_pipeline,
)
from app.services.detection_rules import DetectionRuleEngine
from app.normalization.noise import NoiseFilter


def test_ingestion_scale_100x_accuracy_and_speedup():
    """
    Simulate 100x load (20,000 events) and verify:
      1. Detection parity: SPL prefiltered query misses 0 true attacks.
      2. Prefiltering achieves >= 70% noise reduction.
      3. Processing throughput exceeds 10,000 events/sec.
    """
    raw_events = generate_100x_telemetry(total_events=20000)
    rules = DetectionRuleEngine().get_all_rules()
    noise = NoiseFilter.from_yaml("config/noise.yaml")

    # Baseline
    hits_baseline, groups_baseline = evaluate_pipeline(raw_events, rules, noise)

    # Prefiltered
    t0 = time.perf_counter()
    prefiltered = simulate_spl_prefilter(raw_events)
    hits_opt, groups_opt = evaluate_pipeline(prefiltered, rules, noise)
    elapsed = time.perf_counter() - t0

    throughput = len(raw_events) / elapsed

    # Parity check
    assert len(hits_opt) == len(hits_baseline), "SPL prefilter must not lose any attack hits"
    assert len(groups_opt) == len(groups_baseline), "Grouped alerts count must match exactly"

    # Noise reduction check
    noise_ratio = (len(raw_events) - len(prefiltered)) / len(raw_events)
    assert noise_ratio >= 0.70, f"Expected at least 70% noise reduction, got {noise_ratio:.1%}"

    # Throughput check
    assert throughput > 10000, f"Expected throughput > 10,000 events/sec, got {throughput:,.0f}"
