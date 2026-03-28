"""Baseline evaluation: single-pass LLM classification (no debate).

This provides a comparison point against the multi-agent Red/Blue/Judge
pipeline.  Each sample gets ONE LLM call that classifies the code as
vulnerable or safe and, if vulnerable, identifies the CWE.

Usage:
    python -m scripts.eval_baseline              # all samples
    python -m scripts.eval_baseline --limit 10    # first 10 samples
"""

import argparse
import hashlib
import json
import re
import sys

import mlflow
from langchain_core.prompts import ChatPromptTemplate

from utils.llm import get_llm, get_llm_info
from utils.metrics import SampleResult, classify_sample, compute_metrics
from utils.schemas import (
    BlueTeamDefense,
    DebateReport,
    JudgeVerdict,
    RedTeamFinding,
)

GOLDEN_SET_PATH = "data/golden_set.json"

SYSTEM_PROMPT = """\
You are a security code reviewer. Analyse the submitted code and determine
whether it contains an exploitable vulnerability.

You must respond with ONLY a valid JSON object. No explanation, no markdown,
no backticks.  The object must have exactly these fields:
- vulnerable: boolean (true if the code has a genuine, exploitable vulnerability)
- cwe_id: string or null (e.g. "CWE-89" if vulnerable, null if safe)
- cwe_name: string or null (e.g. "SQL Injection" if vulnerable, null if safe)
- reasoning: string (brief explanation citing specific code evidence)
"""

USER_PROMPT = """\
Review this code for security vulnerabilities:
```
{code}
```
"""


def load_golden_set() -> list[dict]:
    with open(GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _parse_response(raw: str) -> dict:
    """Parse the LLM JSON response, stripping code fences if present."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    raw = re.sub(r"\\'", "'", raw)
    return json.loads(raw)


def _to_debate_report(result: dict) -> DebateReport:
    """Convert a single-pass classification into a DebateReport for metrics."""
    if result["vulnerable"]:
        finding = RedTeamFinding(
            finding_id="F-001",
            cwe_id=result.get("cwe_id") or "CWE-000",
            cwe_name=result.get("cwe_name") or "Unknown",
            severity="high",
            vulnerable_code="(baseline — no snippet)",
            exploit_argument=result.get("reasoning", ""),
        )
        verdict = JudgeVerdict(
            finding_id="F-001",
            confirmed=True,
            reasoning=result.get("reasoning", ""),
            patch=None,
        )
        return DebateReport(
            findings=[finding],
            defenses=[],
            verdicts=[verdict],
        )

    return DebateReport(findings=[], defenses=[], verdicts=[])


def run_baseline(limit: int | None = None):
    samples = load_golden_set()
    if limit is not None:
        samples = samples[:limit]

    llm = get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT),
    ])
    chain = prompt | llm

    results: list[SampleResult] = []
    errors: list[str] = []

    print(f"Running BASELINE evaluation on {len(samples)} golden set samples\n")
    print(f"{'#':<4} {'ID':<26} {'CWE':<8} {'Truth':<12} {'Flagged':<10} {'Class':<6}")
    print("-" * 75)

    for i, sample in enumerate(samples):
        sample_id = sample["id"]
        try:
            response = chain.invoke({"code": sample["code"]})
            result = _parse_response(response.content)
            report = _to_debate_report(result)

            flagged, classification, cwe_flagged, cwe_cls = classify_sample(
                report, sample["has_vulnerability"], sample["cwe_id"],
            )

            results.append(SampleResult(
                sample_id=sample_id,
                cwe_id=sample["cwe_id"],
                has_vulnerability=sample["has_vulnerability"],
                flagged=flagged,
                report=report,
                cwe_flagged=cwe_flagged,
            ))

            truth = "VULN" if sample["has_vulnerability"] else "SAFE"
            flag_str = "YES" if flagged else "NO"
            print(f"{i:<4} {sample_id:<26} {sample['cwe_id']:<8} {truth:<12} {flag_str:<10} {classification:<6}")

        except Exception as e:
            errors.append(f"{sample_id}: {e}")
            print(f"{i:<4} {sample_id:<26} ERROR: {e}")

    if not results:
        print("\nNo successful runs — cannot compute metrics.", file=sys.stderr)
        sys.exit(1)

    # ── Compute metrics ──────────────────────────────────────
    metrics = compute_metrics(results)

    print(f"\n{'='*75}")
    print(f"BASELINE RESULTS ({len(results)}/{len(samples)} samples completed, {len(errors)} errors)\n")
    print(f"  Precision          : {metrics.precision:.3f}")
    print(f"  Recall             : {metrics.recall:.3f}")
    print(f"  F1 Score           : {metrics.f1:.3f}")
    print(f"  False Positive Rate: {metrics.false_positive_rate:.3f}")
    print(f"  TP={metrics.tp}  FP={metrics.fp}  TN={metrics.tn}  FN={metrics.fn}")

    print(f"\n  CWE-Matched Metrics:")
    print(f"  Precision          : {metrics.cwe_precision:.3f}")
    print(f"  Recall             : {metrics.cwe_recall:.3f}")
    print(f"  F1 Score           : {metrics.cwe_f1:.3f}")
    print(f"  False Positive Rate: {metrics.cwe_false_positive_rate:.3f}")
    print(f"  TP={metrics.cwe_tp}  FP={metrics.cwe_fp}  TN={metrics.cwe_tn}  FN={metrics.cwe_fn}")

    print(f"\nPer-CWE breakdown:")
    for cwe_id, cwe in sorted(metrics.per_cwe.items()):
        print(f"  {cwe_id}: P={cwe['precision']:.2f} R={cwe['recall']:.2f} F1={cwe['f1']:.2f}  "
              f"(TP={cwe['tp']} FP={cwe['fp']} TN={cwe['tn']} FN={cwe['fn']})")
        print(f"    CWE-matched: P={cwe['cwe_precision']:.2f} R={cwe['cwe_recall']:.2f} F1={cwe['cwe_f1']:.2f}  "
              f"(TP={cwe['cwe_tp']} FP={cwe['cwe_fp']} TN={cwe['cwe_tn']} FN={cwe['cwe_fn']})")

    # ── Log to MLflow ────────────────────────────────────────
    llm_info = get_llm_info()

    mlflow.set_experiment("code-security-scanner")
    with mlflow.start_run(run_name="baseline-eval"):
        mlflow.log_params({
            "eval_set": "golden_set",
            "eval_set_size": len(samples),
            "method": "baseline-single-pass",
            "completed": len(results),
            "errors": len(errors),
            "llm_backend": llm_info["llm_backend"],
            "llm_model": llm_info["llm_model"],
            "prompt_baseline_sha": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:12],
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
            "cwe_precision": metrics.cwe_precision,
            "cwe_recall": metrics.cwe_recall,
            "cwe_f1": metrics.cwe_f1,
            "cwe_false_positive_rate": metrics.cwe_false_positive_rate,
            "cwe_tp": metrics.cwe_tp,
            "cwe_fp": metrics.cwe_fp,
            "cwe_tn": metrics.cwe_tn,
            "cwe_fn": metrics.cwe_fn,
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

    print(f"\nMLflow run logged (baseline-eval). View with: mlflow ui")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Baseline single-pass evaluation.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only evaluate the first N samples (default: all)")
    args = parser.parse_args()
    run_baseline(limit=args.limit)
