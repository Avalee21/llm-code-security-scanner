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


def _report(
    confirmed_ids: list[str] = None,
    dismissed_ids: list[str] = None,
    cwe: str = "CWE-22",
) -> DebateReport:
    confirmed_ids = confirmed_ids or []
    dismissed_ids = dismissed_ids or []
    findings = [_finding(fid, cwe=cwe) for fid in confirmed_ids + dismissed_ids]
    defenses = [BlueTeamDefense(finding_id=fid, is_false_positive=False, counter_argument="c") for fid in confirmed_ids]
    defenses += [BlueTeamDefense(finding_id=fid, is_false_positive=True, counter_argument="c") for fid in dismissed_ids]
    verdicts = [_verdict(fid, True) for fid in confirmed_ids] + [_verdict(fid, False) for fid in dismissed_ids]
    return DebateReport(findings=findings, defenses=defenses, verdicts=verdicts)


def _sample(sample_id: str, cwe: str, has_vuln: bool, report: DebateReport) -> SampleResult:
    flagged, _, cwe_flagged, _ = classify_sample(report, has_vuln, cwe)
    return SampleResult(
        sample_id=sample_id, cwe_id=cwe, has_vulnerability=has_vuln,
        flagged=flagged, report=report, cwe_flagged=cwe_flagged,
    )


# ---------------------------------------------------------------------------
# classify_sample tests
# ---------------------------------------------------------------------------

def test_classify_tp():
    report = _report(confirmed_ids=["F-001"])
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, has_vulnerability=True)
    assert flagged is True
    assert cls == "TP"
    # No expected_cwe → CWE-matched mirrors base
    assert cwe_flagged is True
    assert cwe_cls == "TP"


def test_classify_fn():
    report = _report(dismissed_ids=["F-001"])
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, has_vulnerability=True)
    assert flagged is False
    assert cls == "FN"
    assert cwe_flagged is False
    assert cwe_cls == "FN"


def test_classify_fp():
    report = _report(confirmed_ids=["F-001"])
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, has_vulnerability=False)
    assert flagged is True
    assert cls == "FP"
    assert cwe_flagged is True
    assert cwe_cls == "FP"


def test_classify_tn():
    report = _report()
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, has_vulnerability=False)
    assert flagged is False
    assert cls == "TN"
    assert cwe_flagged is False
    assert cwe_cls == "TN"


def test_classify_no_findings_vuln_is_fn():
    report = _report()
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, has_vulnerability=True)
    assert flagged is False
    assert cls == "FN"
    assert cwe_flagged is False
    assert cwe_cls == "FN"


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


# ---------------------------------------------------------------------------
# CWE-matched classify_sample tests
# ---------------------------------------------------------------------------

def test_cwe_match_correct_cwe_is_tp():
    """Confirmed finding with matching CWE → both base and CWE-matched say TP."""
    report = _report(confirmed_ids=["F-001"], cwe="CWE-22")
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, True, expected_cwe="CWE-22")
    assert cls == "TP"
    assert cwe_cls == "TP"


def test_cwe_match_wrong_cwe_is_fn():
    """Confirmed finding with wrong CWE → base says TP but CWE-matched says FN."""
    report = _report(confirmed_ids=["F-001"], cwe="CWE-89")
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, True, expected_cwe="CWE-22")
    assert flagged is True
    assert cls == "TP"
    assert cwe_flagged is False
    assert cwe_cls == "FN"


def test_cwe_match_safe_sample_wrong_cwe_both_fp():
    """Safe sample flagged (any CWE) → both base and CWE-matched say FP."""
    report = _report(confirmed_ids=["F-001"], cwe="CWE-89")
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, False, expected_cwe="CWE-89")
    assert cls == "FP"
    assert cwe_cls == "FP"


def test_cwe_match_no_findings_both_tn():
    """No findings on safe sample → both TN."""
    report = _report()
    _, cls, _, cwe_cls = classify_sample(report, False, expected_cwe="CWE-22")
    assert cls == "TN"
    assert cwe_cls == "TN"


def test_cwe_match_mixed_findings_correct_present():
    """Two confirmed findings: one with correct CWE, one wrong → both TP."""
    findings = [_finding("F-001", cwe="CWE-22"), _finding("F-002", cwe="CWE-89")]
    defenses = [
        BlueTeamDefense(finding_id="F-001", is_false_positive=False, counter_argument="c"),
        BlueTeamDefense(finding_id="F-002", is_false_positive=False, counter_argument="c"),
    ]
    verdicts = [_verdict("F-001", True), _verdict("F-002", True)]
    report = DebateReport(findings=findings, defenses=defenses, verdicts=verdicts)

    _, cls, cwe_flagged, cwe_cls = classify_sample(report, True, expected_cwe="CWE-22")
    assert cls == "TP"
    assert cwe_flagged is True
    assert cwe_cls == "TP"


def test_cwe_match_none_fallback_mirrors_base():
    """expected_cwe=None → CWE-matched mirrors base result."""
    report = _report(confirmed_ids=["F-001"], cwe="CWE-89")
    flagged, cls, cwe_flagged, cwe_cls = classify_sample(report, True, expected_cwe=None)
    assert flagged == cwe_flagged
    assert cls == cwe_cls


# ---------------------------------------------------------------------------
# CWE-matched compute_metrics tests
# ---------------------------------------------------------------------------

def test_compute_metrics_cwe_matched_diverges():
    """When system flags wrong CWE, base and CWE-matched metrics diverge."""
    # s1: vuln CWE-22, system confirms CWE-89 → base TP, cwe FN
    wrong_cwe_report = _report(confirmed_ids=["F-001"], cwe="CWE-89")
    s1 = SampleResult(
        sample_id="s1", cwe_id="CWE-22", has_vulnerability=True,
        flagged=True, report=wrong_cwe_report, cwe_flagged=False,
    )
    # s2: safe CWE-22, no findings → both TN
    s2 = _sample("s2", "CWE-22", False, _report())

    m = compute_metrics([s1, s2])

    # Base: 1 TP, 1 TN → perfect
    assert m.tp == 1 and m.fn == 0
    assert m.precision == 1.0
    assert m.recall == 1.0

    # CWE-matched: 0 TP, 1 FN → recall drops
    assert m.cwe_tp == 0 and m.cwe_fn == 1
    assert m.cwe_recall == 0.0


def test_compute_metrics_cwe_matched_agrees_when_correct():
    """When system flags correct CWE, both metric sets agree."""
    results = [
        _sample("s1", "CWE-22", True, _report(confirmed_ids=["F-001"], cwe="CWE-22")),
        _sample("s2", "CWE-22", False, _report()),
    ]
    m = compute_metrics(results)
    assert m.tp == m.cwe_tp == 1
    assert m.tn == m.cwe_tn == 1
    assert m.precision == m.cwe_precision == 1.0
    assert m.recall == m.cwe_recall == 1.0
    assert m.sample_results[0]["classification"] == "TP"
    assert m.sample_results[0]["findings_count"] == 1
