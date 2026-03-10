from agents.judge_patcher import run_judge
from utils.schemas import BlueTeamDefense, JudgeVerdict, RedTeamFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(finding_id: str) -> RedTeamFinding:
    return RedTeamFinding(
        finding_id=finding_id,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity="high",
        vulnerable_code="cursor.execute('SELECT * FROM users WHERE id=' + uid)",
        exploit_argument="uid is unsanitized",
    )


def _defense(finding_id: str, is_false_positive: bool) -> BlueTeamDefense:
    return BlueTeamDefense(
        finding_id=finding_id,
        is_false_positive=is_false_positive,
        counter_argument="Stub counter argument",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_judge_all_confirmed():
    findings = [_finding("F-001"), _finding("F-002")]
    defenses = [
        _defense("F-001", is_false_positive=False),
        _defense("F-002", is_false_positive=False),
    ]
    verdicts = run_judge(findings, defenses)

    assert len(verdicts) == 2
    assert all(v.confirmed is True for v in verdicts)
    assert all(v.patch is None for v in verdicts)


def test_judge_all_false_positive():
    findings = [_finding("F-001"), _finding("F-002")]
    defenses = [
        _defense("F-001", is_false_positive=True),
        _defense("F-002", is_false_positive=True),
    ]
    verdicts = run_judge(findings, defenses)

    assert len(verdicts) == 2
    assert all(v.confirmed is False for v in verdicts)


def test_judge_mixed():
    findings = [_finding("F-001"), _finding("F-002")]
    defenses = [
        _defense("F-001", is_false_positive=False),
        _defense("F-002", is_false_positive=True),
    ]
    verdicts = run_judge(findings, defenses)

    assert len(verdicts) == 2
    verdict_map = {v.finding_id: v for v in verdicts}
    assert verdict_map["F-001"].confirmed is True
    assert verdict_map["F-002"].confirmed is False


def test_judge_no_defenses():
    findings = [_finding("F-001"), _finding("F-002"), _finding("F-003")]
    verdicts = run_judge(findings, defenses=[])

    assert len(verdicts) == 3
    assert all(v.confirmed is True for v in verdicts)


def test_judge_mismatched_finding_ids():
    findings = [_finding("F-001")]
    defenses = [_defense("F-999", is_false_positive=True)]
    verdicts = run_judge(findings, defenses)

    assert len(verdicts) == 1
    assert verdicts[0].finding_id == "F-001"
    assert verdicts[0].confirmed is True


def test_judge_returns_judge_verdict_instances():
    findings = [_finding("F-001")]
    defenses = [_defense("F-001", is_false_positive=False)]
    verdicts = run_judge(findings, defenses)

    assert isinstance(verdicts, list)
    assert isinstance(verdicts[0], JudgeVerdict)


def test_judge_preserves_finding_id_in_verdict():
    findings = [_finding("F-042")]
    verdicts = run_judge(findings, defenses=[])

    assert verdicts[0].finding_id == "F-042"


def test_judge_reasoning_is_nonempty():
    findings = [_finding("F-001"), _finding("F-002")]
    defenses = [_defense("F-001", is_false_positive=True)]
    verdicts = run_judge(findings, defenses)

    assert all(len(v.reasoning) > 0 for v in verdicts)


def test_judge_empty_inputs():
    verdicts = run_judge(findings=[], defenses=[])
    assert verdicts == []
