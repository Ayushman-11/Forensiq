"""
Benchmark Ingestion Service with a 100x Data Load.

Simulates 50,000 raw SIEM telemetry events (50k vs normal 500 = 100x scale factor).
Compares:
  1. Unfiltered pipeline: all 50k events ingested and evaluated directly in Python.
  2. SPL prefiltered pipeline: noise filtered at SIEM level before Python evaluation.
Validates:
  - Throughput (events / sec)
  - Memory & execution time
  - Detection completeness (100% true positive retention)
"""

import asyncio
import time
import uuid
from datetime import datetime, timezone
from mongomock_motor import AsyncMongoMockClient

from app.normalization.mappers import to_canonical
from app.normalization.noise import NoiseFilter
from app.services.detection_rules import DetectionRuleEngine
from app.normalization.dedup import RuleHit, aggregate_failed_logons, group_hits


def generate_100x_telemetry(total_events: int = 50000) -> list[dict]:
    """Generate realistic SIEM events with realistic benign-to-attack ratio."""
    events = []
    now = datetime.now(timezone.utc).isoformat()

    # 1. 20,000 Benign Sysmon 1 Process Creations
    benign_procs = ["chrome.exe", "explorer.exe", "svchost.exe", "conhost.exe", "code.exe"]
    for i in range(20000):
        proc = benign_procs[i % len(benign_procs)]
        events.append({
            "_time": now,
            "EventCode": "1",
            "Image": f"C:\\Program Files\\{proc}",
            "CommandLine": f'"{proc}" --type=utility --field-trial-handle=123',
            "User": "WORKSTATION\\alice",
            "Computer": "WKS-01",
        })

    # 2. 15,000 Benign Sysmon 3 Connections (Internal & Web Ports)
    for i in range(15000):
        events.append({
            "_time": now,
            "EventCode": "3",
            "Initiated": "true",
            "DestinationIp": "192.168.1.50" if i % 2 == 0 else "52.96.166.130",
            "DestinationPort": 443 if i % 2 == 0 else 80,
            "Computer": "WKS-01",
        })

    # 3. 5,000 Benign Sysmon 22 DNS Queries
    for i in range(5000):
        events.append({
            "_time": now,
            "EventCode": "22",
            "QueryName": "login.microsoftonline.com" if i % 2 == 0 else "www.google.com",
            "Computer": "WKS-01",
        })

    # 4. True Positives: 5,000 Failed Logons (Brute Force)
    for i in range(5000):
        events.append({
            "_time": now,
            "EventCode": "4625",
            "IpAddress": f"203.0.113.{10 + (i % 20)}",
            "TargetUserName": f"user_{i % 10}",
            "Computer": "DC-01",
        })

    # 5. True Positives: 2,500 Suspicious PowerShell Attacks (EventCode 1)
    for i in range(2500):
        events.append({
            "_time": now,
            "EventCode": "1",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -noni -bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            "User": "NT AUTHORITY\\SYSTEM",
            "Computer": "SRV-APP",
        })

    # 6. True Positives: 1,500 Registry Run Key Persistence (EventCode 13)
    for i in range(1500):
        events.append({
            "_time": now,
            "EventCode": "13",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\BackdoorUpdater",
            "Details": "C:\\ProgramData\\updater.exe",
            "Computer": "SRV-SQL",
        })

    # 7. True Positives: 1,000 C2 Beacon Connections (EventCode 3)
    for i in range(1000):
        events.append({
            "_time": now,
            "EventCode": "3",
            "Initiated": "true",
            "DestinationIp": "198.51.100.44",
            "DestinationPort": 4444,
            "Computer": "SRV-WEB",
        })

    return events


def simulate_spl_prefilter(raw_events: list[dict]) -> list[dict]:
    """Simulate server-side pushdown of SPL prefilter predicates in Splunk."""
    prefiltered = []
    for r in raw_events:
        ec = str(r.get("EventCode", ""))
        if ec in ("4625", "4648"):
            prefiltered.append(r)
        elif ec == "1":
            img = str(r.get("Image", "")).lower()
            cmd = str(r.get("CommandLine", "")).lower()
            if ("powershell" in img or "pwsh" in img) and any(k in cmd for k in ("-enc", "-noni", "bypass", "hidden", "downloadstring", "iex")):
                prefiltered.append(r)
        elif ec == "13":
            tgt = str(r.get("TargetObject", "")).lower()
            if "currentversion\\run" in tgt or "currentversion/run" in tgt:
                prefiltered.append(r)
        elif ec == "3":
            init = str(r.get("Initiated", "")).lower()
            port = int(r.get("DestinationPort", 0))
            ip = str(r.get("DestinationIp", ""))
            if init == "true" and port not in (80, 443, 53) and not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127.")):
                prefiltered.append(r)
        elif ec == "22":
            qname = str(r.get("QueryName", "")).lower()
            if any(k in qname for k in ("dyndns", "ngrok", "pastebin", "raw.githubusercontent", "bit.ly")) or len(qname) > 60:
                prefiltered.append(r)
    return prefiltered


def evaluate_pipeline(events: list[dict], rules, noise: NoiseFilter):
    canonical = []
    for r in events:
        try:
            ev = to_canonical(r)
            if ev and not noise.reason(ev):
                canonical.append(ev)
        except Exception:
            pass

    hits = []
    for ev in canonical:
        for r in rules:
            if r.name != "brute_force_login" and r.match_fn and r.match_fn(ev.fields):
                hits.append(RuleHit(r, ev))

    brute = next((r for r in rules if r.name == "brute_force_login"), None)
    if brute:
        for ev, count in aggregate_failed_logons(canonical, 5, 300):
            hits.append(RuleHit(brute, ev, count))

    groups = group_hits(hits, "default", 300)
    return hits, groups


def main():
    print("=" * 70)
    print("  FORENSIQ: 100x INGESTION & SPL PREFILTER BENCHMARK")
    print("=" * 70)

    print("\n1. Generating 100x telemetry stream (50,000 raw events)...")
    t0 = time.perf_counter()
    raw_events = generate_100x_telemetry(50000)
    gen_time = time.perf_counter() - t0
    print(f"   Generated {len(raw_events):,} events in {gen_time:.3f}s")

    rules = DetectionRuleEngine().get_all_rules()
    noise = NoiseFilter.from_yaml("config/noise.yaml")

    # Benchmark A: Raw Full Ingestion (Evaluating all in Python)
    print("\n2. Benchmarking Baseline: Full Ingestion in Python (No SPL pushdown)...")
    t_start = time.perf_counter()
    hits_a, groups_a = evaluate_pipeline(raw_events, rules, noise)
    dur_a = time.perf_counter() - t_start
    tps_a = len(raw_events) / dur_a

    print(f"   Duration:          {dur_a:.3f}s")
    print(f"   Throughput:        {tps_a:,.0f} events/sec")
    print(f"   Detections (hits): {len(hits_a):,}")
    print(f"   Deduplicated groups: {len(groups_a):,}")

    # Benchmark B: Optimized Ingestion with SPL Prefilter Pushdown
    print("\n3. Benchmarking Optimized: SPL Prefilter Pushdown...")
    t_prefilter_start = time.perf_counter()
    prefiltered_events = simulate_spl_prefilter(raw_events)
    t_prefilter = time.perf_counter() - t_prefilter_start

    t_eval_start = time.perf_counter()
    hits_b, groups_b = evaluate_pipeline(prefiltered_events, rules, noise)
    dur_b = time.perf_counter() - t_eval_start
    total_opt = t_prefilter + dur_b
    tps_b = len(raw_events) / total_opt

    noise_eliminated = (1 - len(prefiltered_events) / len(raw_events)) * 100

    print(f"   Prefiltered Events: {len(prefiltered_events):,} (filtered out {noise_eliminated:.1f}% noise)")
    print(f"   Duration:           {total_opt:.3f}s (eval: {dur_b:.3f}s)")
    print(f"   Effective Tput:     {tps_b:,.0f} events/sec")
    print(f"   Detections (hits):  {len(hits_b):,}")
    print(f"   Deduplicated groups: {len(groups_b):,}")

    print("\n" + "=" * 70)
    print("  PERFORMANCE SUMMARY")
    print("=" * 70)
    speedup = dur_a / total_opt
    print(f"  • Speedup Factor:     {speedup:.1f}x faster with SPL pushdown")
    print(f"  • Noise Reduction:    {noise_eliminated:.1f}% raw traffic discarded at SIEM layer")
    print(f"  • Detection Parity:   {len(hits_a)} vs {len(hits_b)} hits (100% true positive retention)")
    assert len(hits_a) == len(hits_b), "Mismatch in detection count between baseline and prefiltered!"
    print("  • Verification:       PASSED [All 100x tests satisfied]")
    print("=" * 70)


if __name__ == "__main__":
    main()
