"""
Standalone CLI Evaluation Benchmark Runner.
Executes the evaluation harness and returns exit code 0 on pass or 1 on regression.
Usage:
    python scripts/run_eval.py
"""

import asyncio
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.eval_harness import run_evaluation_benchmark, EvaluationRegressionError


async def main():
    print("=" * 60)
    print("Forensiq AI Investigation Evaluation Benchmark")
    print("=" * 60)
    try:
        summary = await run_evaluation_benchmark(enforce_thresholds=True)
        print(f"Total Samples Tested : {summary['total_samples']}")
        print(f"Confusion Matrix     : {summary['confusion_matrix']}")
        print(f"Precision            : {summary['precision']:.2%} (Target: >= {summary['min_precision_threshold']:.0%})")
        print(f"Recall               : {summary['recall']:.2%} (Target: >= {summary['min_recall_threshold']:.0%})")
        print(f"F1-Score             : {summary['f1_score']:.2%}")
        print(f"Overall Accuracy     : {summary['accuracy']:.2%}")
        print("\nAll evaluation quality thresholds PASSED. Safe to release.")
        sys.exit(0)
    except EvaluationRegressionError as e:
        print(f"\n[ERROR] REGRESSION DETECTED: {e}", file=sys.stderr)
        print("Release blocked.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected evaluation failure: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(main())

