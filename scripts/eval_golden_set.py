"""Batch evaluation: run the full pipeline on all golden set samples and log to MLflow."""

import json
import sys
import time

import mlflow

from orchestrator.graph import run_pipeline
from utils.metrics import SampleResult, classify_sample, compute_metrics

GOLDEN_SET_PATH = "data/golden_set.json"


def load_golden_set() -> list[dict]:
    with open(GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def run_evaluation():
    samples = load_golden_set()
    results: list[SampleResult] = []
    errors: list[str] = []

    print(f"Running evaluation on {len(samples)} golden set samples\n")
    print(f"{'#':<4} {'ID':<26} {'CWE':<8} {'Truth':<12} {'Flagged':<10} {'Class':<6} {'Findings'}")
    print("-" * 90)

    for i, sample in enumerate(samples):
        sample_id = sample["id"]
        try:
            report = run_pipeline(sample["code"], track=False)
            flagged, classification = classify_sample(report, sample["has_vulnerability"])

            results.append(SampleResult(
                sample_id=sample_id,
                cwe_id=sample["cwe_id"],
                has_vulnerability=sample["has_vulnerability"],
                flagged=flagged,
                report=report,
            ))

            truth = "VULN" if sample["has_vulnerability"] else "SAFE"
            flag_str = "YES" if flagged else "NO"
            n_findings = len(report.findings)
            print(f"{i:<4} {sample_id:<26} {sample['cwe_id']:<8} {truth:<12} {flag_str:<10} {classification:<6} {n_findings}")

        except Exception as e:
            errors.append(f"{sample_id}: {e}")
            print(f"{i:<4} {sample_id:<26} ERROR: {e}")

    if not results:
        print("\nNo successful runs — cannot compute metrics.", file=sys.stderr)
        sys.exit(1)

    # ── Compute metrics ──────────────────────────────────────
    metrics = compute_metrics(results)

    print(f"\n{'='*90}")
    print(f"RESULTS ({len(results)}/{len(samples)} samples completed, {len(errors)} errors)\n")
    print(f"  Precision          : {metrics.precision:.3f}")
    print(f"  Recall             : {metrics.recall:.3f}")
    print(f"  F1 Score           : {metrics.f1:.3f}")
    print(f"  False Positive Rate: {metrics.false_positive_rate:.3f}")
    print(f"  TP={metrics.tp}  FP={metrics.fp}  TN={metrics.tn}  FN={metrics.fn}")

    print(f"\nPer-CWE breakdown:")
    for cwe_id, cwe in sorted(metrics.per_cwe.items()):
        print(f"  {cwe_id}: P={cwe['precision']:.2f} R={cwe['recall']:.2f} F1={cwe['f1']:.2f}  "
              f"(TP={cwe['tp']} FP={cwe['fp']} TN={cwe['tn']} FN={cwe['fn']})")

    # ── Log to MLflow ────────────────────────────────────────
    mlflow.set_experiment("code-security-scanner")
    with mlflow.start_run(run_name="golden-set-eval"):
        mlflow.log_params({
            "eval_set": "golden_set",
            "eval_set_size": len(samples),
            "completed": len(results),
            "errors": len(errors),
        })
        mlflow.log_metrics({
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "false_positive_rate": metrics.false_positive_rate,
            "tp": metrics.tp,
            "fp": metrics.fp,
            "tn": metrics.tn,
            "fn": metrics.fn,
        })
        mlflow.log_text(
            json.dumps(metrics.sample_results, indent=2),
            "per_sample_results.json",
        )
        mlflow.log_text(
            json.dumps(metrics.per_cwe, indent=2),
            "per_cwe_results.json",
        )
        if errors:
            mlflow.log_text("\n".join(errors), "errors.txt")

    print(f"\nMLflow run logged. View with: mlflow ui")


if __name__ == "__main__":
    run_evaluation()
