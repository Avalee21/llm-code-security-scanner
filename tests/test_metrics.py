from utils.metrics import SampleResult, classify_sample, compute_metrics, EvalMetrics
from utils.schemas import (
    BlueTeamDefense,
    DebateReport,
    JudgeVerdict,
    RedTeamFinding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(fid: str = "F-001", cwe: str = "CWE-22") -> RedTeamFinding:
    return RedTeamFinding(
        finding_id=fid, cwe_id=cwe, cwe_name="Test",
        severity="high", vulnerable_code="x", exploit_argument="y",
    )


def _verdict(fid: str = "F-001", confirmed: bool = True) -> JudgeVerdict:
    return JudgeVerdict(finding_id=fid, confirmed=confirmed, reasoning="r", patch=None)


def _report(confirmed_ids: list[str] = None, dismissed_ids: list[str] = None) -> DebateReport:
    confirmed_ids = confirmed_ids or []
    dismissed_ids = dismissed_ids or []
    findings = [_finding(fid) for fid in confirmed_ids + dismissed_ids]
    defenses = [BlueTeamDefense(finding_id=fid, is_false_positive=False, counter_argument="c") for fid in confirmed_ids]
    defenses += [BlueTeamDefense(finding_id=fid, is_false_positive=True, counter_argument="c") for fid in dismissed_ids]
    verdicts = [_verdict(fid, True) for fid in confirmed_ids] + [_verdict(fid, False) for fid in dismissed_ids]
    return DebateReport(findings=findings, defenses=defenses, verdicts=verdicts)


def _sample(sample_id: str, cwe: str, has_vuln: bool, report: DebateReport) -> SampleResult:
    flagged = any(v.confirmed for v in report.verdicts)
    return SampleResult(sample_id=sample_id, cwe_id=cwe, has_vulnerability=has_vuln, flagged=flagged, report=report)


# ---------------------------------------------------------------------------
# classify_sample tests
# ---------------------------------------------------------------------------

def test_classify_tp():
    report = _report(confirmed_ids=["F-001"])
    flagged, cls = classify_sample(report, has_vulnerability=True)
    assert flagged is True
    assert cls == "TP"


def test_classify_fn():
    report = _report(dismissed_ids=["F-001"])
    flagged, cls = classify_sample(report, has_vulnerability=True)
    assert flagged is False
    assert cls == "FN"


def test_classify_fp():
    report = _report(confirmed_ids=["F-001"])
    flagged, cls = classify_sample(report, has_vulnerability=False)
    assert flagged is True
    assert cls == "FP"


def test_classify_tn():
    report = _report()
    flagged, cls = classify_sample(report, has_vulnerability=False)
    assert flagged is False
    assert cls == "TN"


def test_classify_no_findings_vuln_is_fn():
    report = _report()
    flagged, cls = classify_sample(report, has_vulnerability=True)
    assert flagged is False
    assert cls == "FN"


# ---------------------------------------------------------------------------
# compute_metrics tests
# ---------------------------------------------------------------------------

def test_perfect_metrics():
    results = [
        _sample("s1", "CWE-22", True, _report(confirmed_ids=["F-001"])),   # TP
        _sample("s2", "CWE-22", False, _report()),                          # TN
        _sample("s3", "CWE-89", True, _report(confirmed_ids=["F-001"])),   # TP
        _sample("s4", "CWE-89", False, _report()),                          # TN
    ]
    m = compute_metrics(results)
    assert m.tp == 2 and m.fp == 0 and m.tn == 2 and m.fn == 0
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.false_positive_rate == 0.0


def test_all_false_positives():
    results = [
        _sample("s1", "CWE-22", False, _report(confirmed_ids=["F-001"])),  # FP
        _sample("s2", "CWE-22", False, _report(confirmed_ids=["F-001"])),  # FP
    ]
    m = compute_metrics(results)
    assert m.tp == 0 and m.fp == 2
    assert m.precision == 0.0
    assert m.false_positive_rate == 1.0


def test_all_misses():
    results = [
        _sample("s1", "CWE-22", True, _report()),  # FN
        _sample("s2", "CWE-22", True, _report()),  # FN
    ]
    m = compute_metrics(results)
    assert m.fn == 2
    assert m.recall == 0.0


def test_mixed_results():
    results = [
        _sample("s1", "CWE-22", True, _report(confirmed_ids=["F-001"])),   # TP
        _sample("s2", "CWE-22", True, _report()),                           # FN
        _sample("s3", "CWE-22", False, _report(confirmed_ids=["F-001"])),  # FP
        _sample("s4", "CWE-22", False, _report()),                          # TN
    ]
    m = compute_metrics(results)
    assert m.tp == 1 and m.fp == 1 and m.tn == 1 and m.fn == 1
    assert m.precision == 0.5
    assert m.recall == 0.5
    assert abs(m.f1 - 0.5) < 1e-9
    assert m.false_positive_rate == 0.5


def test_per_cwe_breakdown():
    results = [
        _sample("s1", "CWE-22", True, _report(confirmed_ids=["F-001"])),  # TP
        _sample("s2", "CWE-22", False, _report()),                         # TN
        _sample("s3", "CWE-89", True, _report()),                          # FN
        _sample("s4", "CWE-89", False, _report(confirmed_ids=["F-001"])), # FP
    ]
    m = compute_metrics(results)

    assert "CWE-22" in m.per_cwe
    assert m.per_cwe["CWE-22"]["tp"] == 1
    assert m.per_cwe["CWE-22"]["tn"] == 1
    assert m.per_cwe["CWE-22"]["precision"] == 1.0

    assert "CWE-89" in m.per_cwe
    assert m.per_cwe["CWE-89"]["fn"] == 1
    assert m.per_cwe["CWE-89"]["fp"] == 1
    assert m.per_cwe["CWE-89"]["recall"] == 0.0


def test_sample_results_populated():
    results = [
        _sample("s1", "CWE-22", True, _report(confirmed_ids=["F-001"])),
    ]
    m = compute_metrics(results)
    assert len(m.sample_results) == 1
    assert m.sample_results[0]["sample_id"] == "s1"
    assert m.sample_results[0]["classification"] == "TP"
    assert m.sample_results[0]["findings_count"] == 1
