"""Evaluation metrics for the code security scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from utils.schemas import DebateReport


@dataclass
class SampleResult:
    sample_id: str
    cwe_id: str
    has_vulnerability: bool  # ground truth
    flagged: bool            # system said vulnerable (≥1 confirmed finding)
    report: DebateReport


@dataclass
class EvalMetrics:
    tp: int = 0   # vulnerable sample correctly flagged
    fp: int = 0   # safe sample incorrectly flagged
    tn: int = 0   # safe sample correctly cleared
    fn: int = 0   # vulnerable sample missed

    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0

    per_cwe: dict[str, dict] = field(default_factory=dict)
    sample_results: list[dict] = field(default_factory=list)


def classify_sample(report: DebateReport, has_vulnerability: bool) -> tuple[bool, str]:
    """Classify a pipeline result against ground truth.
    Returns (flagged, classification) where classification is TP/FP/TN/FN."""
    flagged = any(v.confirmed for v in report.verdicts)

    if has_vulnerability and flagged:
        return flagged, "TP"
    elif has_vulnerability and not flagged:
        return flagged, "FN"
    elif not has_vulnerability and flagged:
        return flagged, "FP"
    else:
        return flagged, "TN"


def compute_metrics(results: list[SampleResult]) -> EvalMetrics:
    """Compute aggregate precision, recall, F1, and per-CWE breakdown."""
    metrics = EvalMetrics()
    per_cwe: dict[str, dict[str, int]] = {}

    for r in results:
        _, classification = classify_sample(r.report, r.has_vulnerability)

        # Aggregate counts
        if classification == "TP":
            metrics.tp += 1
        elif classification == "FP":
            metrics.fp += 1
        elif classification == "TN":
            metrics.tn += 1
        elif classification == "FN":
            metrics.fn += 1

        # Per-CWE counts
        if r.cwe_id not in per_cwe:
            per_cwe[r.cwe_id] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        per_cwe[r.cwe_id][classification.lower()] += 1

        # Per-sample record
        metrics.sample_results.append({
            "sample_id": r.sample_id,
            "cwe_id": r.cwe_id,
            "ground_truth": r.has_vulnerability,
            "flagged": r.flagged,
            "classification": classification,
            "findings_count": len(r.report.findings),
            "confirmed_count": sum(1 for v in r.report.verdicts if v.confirmed),
        })

    # Aggregate rates
    if metrics.tp + metrics.fp > 0:
        metrics.precision = metrics.tp / (metrics.tp + metrics.fp)
    if metrics.tp + metrics.fn > 0:
        metrics.recall = metrics.tp / (metrics.tp + metrics.fn)
    if metrics.precision + metrics.recall > 0:
        metrics.f1 = 2 * metrics.precision * metrics.recall / (metrics.precision + metrics.recall)
    if metrics.fp + metrics.tn > 0:
        metrics.false_positive_rate = metrics.fp / (metrics.fp + metrics.tn)

    # Per-CWE rates
    for cwe_id, counts in per_cwe.items():
        cwe_p = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] > 0 else 0.0
        cwe_r = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] > 0 else 0.0
        cwe_f1 = 2 * cwe_p * cwe_r / (cwe_p + cwe_r) if cwe_p + cwe_r > 0 else 0.0
        metrics.per_cwe[cwe_id] = {**counts, "precision": cwe_p, "recall": cwe_r, "f1": cwe_f1}

    return metrics
