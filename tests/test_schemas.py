from utils.schemas import RedTeamFinding, BlueTeamDefense, JudgeVerdict, DebateReport


def test_red_team_finding_valid():
    f = RedTeamFinding(
        finding_id="F-001",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity="critical",
        vulnerable_code="query = 'SELECT * FROM users WHERE id=' + user_id",
        exploit_argument="user_id is unsanitized and passed directly into the query"
    )
    assert f.cwe_id == "CWE-89"


def test_blue_team_defense_valid():
    d = BlueTeamDefense(
        finding_id="F-001",
        is_false_positive=False,
        counter_argument="No input validation found elsewhere in the codebase"
    )
    assert d.is_false_positive is False


def test_judge_verdict_with_patch():
    v = JudgeVerdict(
        finding_id="F-001",
        confirmed=True,
        reasoning="Red Team argument is stronger, no sanitization present",
        patch="query = 'SELECT * FROM users WHERE id = %s', (user_id,)"
    )
    assert v.confirmed is True
    assert v.patch is not None


def test_debate_report_assembles():
    report = DebateReport(findings=[], defenses=[], verdicts=[])
    assert report.verification_passed is None