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
    cwe_flagged: bool = False  # system confirmed a finding with matching CWE


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

    # CWE-matched metrics (only counts TPs where the correct CWE was identified)
    cwe_tp: int = 0
    cwe_fp: int = 0
    cwe_tn: int = 0
    cwe_fn: int = 0

    cwe_precision: float = 0.0
    cwe_recall: float = 0.0
    cwe_f1: float = 0.0
    cwe_false_positive_rate: float = 0.0

    # Per-finding metrics (how noisy is the Red Team?)
    total_findings: int = 0
    total_confirmed: int = 0
    cwe_matched_confirmed: int = 0
    irrelevant_confirmed: int = 0   # confirmed findings with wrong CWE on vulnerable samples
    finding_precision: float = 0.0  # cwe_matched_confirmed / total_confirmed

    per_cwe: dict[str, dict] = field(default_factory=dict)
    sample_results: list[dict] = field(default_factory=list)


def final_verdicts(report: DebateReport):
    """Return merged verdicts: round2 verdicts override round1 where present."""
    if report.round2_verdicts is None:
        return report.verdicts
    # Round 2 only covers findings that were confirmed in round 1.
    # Merge: use round 2 verdict when available, fall back to round 1.
    r2_map = {v.finding_id: v for v in report.round2_verdicts}
    return [r2_map.get(v.finding_id, v) for v in report.verdicts]


def _cwe_matched_flag(report: DebateReport, expected_cwe: str) -> bool:
    """Return True if any confirmed verdict's finding has a CWE matching *expected_cwe*."""
    cwe_by_finding = {f.finding_id: f.cwe_id for f in report.findings}
    return any(
        cwe_by_finding.get(v.finding_id) == expected_cwe
        for v in final_verdicts(report)
        if v.confirmed
    )


def classify_sample(
    report: DebateReport,
    has_vulnerability: bool,
    expected_cwe: str | None = None,
) -> tuple[bool, str, bool, str]:
    """Classify a pipeline result against ground truth.

    Returns (flagged, classification, cwe_flagged, cwe_classification).
    *flagged* / *classification* use the original any-confirmed logic.
    *cwe_flagged* / *cwe_classification* only count a hit when a confirmed
    finding carries the correct CWE.  When *expected_cwe* is ``None`` the
    CWE-matched result mirrors the base result.
    """
    flagged = any(v.confirmed for v in final_verdicts(report))

    if expected_cwe is not None:
        if has_vulnerability:
            # Vulnerable sample: only count TP when correct CWE confirmed
            cwe_flagged = _cwe_matched_flag(report, expected_cwe)
        else:
            # Safe sample: any confirmed finding is FP regardless of CWE
            cwe_flagged = flagged
    else:
        cwe_flagged = flagged

    def _label(vuln: bool, flag: bool) -> str:
        if vuln and flag:
            return "TP"
        elif vuln and not flag:
            return "FN"
        elif not vuln and flag:
            return "FP"
        else:
            return "TN"

    return flagged, _label(has_vulnerability, flagged), cwe_flagged, _label(has_vulnerability, cwe_flagged)


def compute_metrics(results: list[SampleResult]) -> EvalMetrics:
    """Compute aggregate precision, recall, F1, and per-CWE breakdown."""
    metrics = EvalMetrics()
    per_cwe: dict[str, dict[str, int]] = {}

    for r in results:
        _, classification, _, cwe_classification = classify_sample(
            r.report, r.has_vulnerability, r.cwe_id,
        )

        # Aggregate counts
        if classification == "TP":
            metrics.tp += 1
        elif classification == "FP":
            metrics.fp += 1
        elif classification == "TN":
            metrics.tn += 1
        elif classification == "FN":
            metrics.fn += 1

        # CWE-matched aggregate counts
        if cwe_classification == "TP":
            metrics.cwe_tp += 1
        elif cwe_classification == "FP":
            metrics.cwe_fp += 1
        elif cwe_classification == "TN":
            metrics.cwe_tn += 1
        elif cwe_classification == "FN":
            metrics.cwe_fn += 1

        # Per-CWE counts
        if r.cwe_id not in per_cwe:
            per_cwe[r.cwe_id] = {
                "tp": 0, "fp": 0, "tn": 0, "fn": 0,
                "cwe_tp": 0, "cwe_fp": 0, "cwe_tn": 0, "cwe_fn": 0,
            }
        per_cwe[r.cwe_id][classification.lower()] += 1
        per_cwe[r.cwe_id][f"cwe_{cwe_classification.lower()}"] += 1

        # Per-finding counts
        cwe_by_finding = {f.finding_id: f.cwe_id for f in r.report.findings}
        n_findings = len(r.report.findings)
        n_confirmed = sum(1 for v in final_verdicts(r.report) if v.confirmed)
        n_cwe_matched = sum(
            1 for v in final_verdicts(r.report)
            if v.confirmed and cwe_by_finding.get(v.finding_id) == r.cwe_id
        )
        n_irrelevant = sum(
            1 for v in final_verdicts(r.report)
            if v.confirmed and cwe_by_finding.get(v.finding_id) != r.cwe_id
        ) if r.has_vulnerability else 0
        metrics.total_findings += n_findings
        metrics.total_confirmed += n_confirmed
        metrics.cwe_matched_confirmed += n_cwe_matched
        metrics.irrelevant_confirmed += n_irrelevant

        # Per-sample record
        metrics.sample_results.append({
            "sample_id": r.sample_id,
            "cwe_id": r.cwe_id,
            "ground_truth": r.has_vulnerability,
            "flagged": r.flagged,
            "classification": classification,
            "cwe_flagged": r.cwe_flagged,
            "cwe_classification": cwe_classification,
            "findings_count": n_findings,
            "confirmed_count": n_confirmed,
            "cwe_matched_confirmed_count": n_cwe_matched,
            "irrelevant_count": n_irrelevant,
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

    # CWE-matched aggregate rates
    if metrics.cwe_tp + metrics.cwe_fp > 0:
        metrics.cwe_precision = metrics.cwe_tp / (metrics.cwe_tp + metrics.cwe_fp)
    if metrics.cwe_tp + metrics.cwe_fn > 0:
        metrics.cwe_recall = metrics.cwe_tp / (metrics.cwe_tp + metrics.cwe_fn)
    if metrics.cwe_precision + metrics.cwe_recall > 0:
        metrics.cwe_f1 = 2 * metrics.cwe_precision * metrics.cwe_recall / (metrics.cwe_precision + metrics.cwe_recall)
    if metrics.cwe_fp + metrics.cwe_tn > 0:
        metrics.cwe_false_positive_rate = metrics.cwe_fp / (metrics.cwe_fp + metrics.cwe_tn)

    # Per-finding precision
    if metrics.total_confirmed > 0:
        metrics.finding_precision = metrics.cwe_matched_confirmed / metrics.total_confirmed

    # Per-CWE rates
    for cwe_id, counts in per_cwe.items():
        cwe_p = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] > 0 else 0.0
        cwe_r = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] > 0 else 0.0
        cwe_f1 = 2 * cwe_p * cwe_r / (cwe_p + cwe_r) if cwe_p + cwe_r > 0 else 0.0
        m_p = counts["cwe_tp"] / (counts["cwe_tp"] + counts["cwe_fp"]) if counts["cwe_tp"] + counts["cwe_fp"] > 0 else 0.0
        m_r = counts["cwe_tp"] / (counts["cwe_tp"] + counts["cwe_fn"]) if counts["cwe_tp"] + counts["cwe_fn"] > 0 else 0.0
        m_f1 = 2 * m_p * m_r / (m_p + m_r) if m_p + m_r > 0 else 0.0
        metrics.per_cwe[cwe_id] = {
            **counts,
            "precision": cwe_p, "recall": cwe_r, "f1": cwe_f1,
            "cwe_precision": m_p, "cwe_recall": m_r, "cwe_f1": m_f1,
        }

    return metrics
