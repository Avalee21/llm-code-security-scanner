import json
from unittest.mock import MagicMock, patch

from agents.blue_team import run_blue_team_round2
from agents.judge_patcher import run_judge_round2
from orchestrator.graph import blue_team_r2_node, PipelineState
from utils.metrics import final_verdicts
from utils.schemas import BlueTeamDefense, DebateReport, JudgeVerdict, RedTeamFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(fid="F-001", cwe_id="CWE-22"):
    return RedTeamFinding(
        finding_id=fid,
        cwe_id=cwe_id,
        cwe_name="Path Traversal",
        severity="high",
        vulnerable_code="open(user_input)",
        exploit_argument="user_input is unsanitized",
    )


def _defense(fid="F-001", is_fp=False):
    return BlueTeamDefense(
        finding_id=fid,
        is_false_positive=is_fp,
        counter_argument="Round 1 counter argument",
    )


def _verdict(fid="F-001", confirmed=True):
    return JudgeVerdict(
        finding_id=fid,
        confirmed=confirmed,
        reasoning="Confirmed in round 1",
        patch=None,
    )


def _mock_response(payload):
    mock = MagicMock()
    mock.content = json.dumps(payload)
    return mock


def _run_blue_team_r2_with_mock(confirmed_findings, code, round1_defenses, payload):
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)
    with patch("agents.blue_team.get_llm"), \
         patch("agents.blue_team.ChatPromptTemplate") as mock_cls:
        mock_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_blue_team_round2(confirmed_findings, code, round1_defenses)


def _run_judge_r2_with_mock(confirmed_findings, r1_verdicts, r2_defenses, code, payload):
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)
    with patch("agents.judge_patcher.get_llm"), \
         patch("agents.judge_patcher.ChatPromptTemplate") as mock_cls:
        mock_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_judge_round2(confirmed_findings, r1_verdicts, r2_defenses, code)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_blue_team_r2_sends_only_confirmed_findings():
    """run_blue_team_round2 is called with confirmed findings and returns defenses."""
    confirmed = [_finding("F-001")]
    r1_defenses = [_defense("F-001")]
    payload = [{"finding_id": "F-001", "is_false_positive": True, "counter_argument": "New strong argument"}]

    result = _run_blue_team_r2_with_mock(confirmed, "code", r1_defenses, payload)

    assert len(result) == 1
    assert result[0].finding_id == "F-001"
    assert result[0].is_false_positive is True


def test_judge_r2_can_flip_confirmed_to_dismissed():
    """run_judge_round2 can flip a confirmed finding to dismissed."""
    confirmed = [_finding("F-001")]
    r1_verdicts = [_verdict("F-001", confirmed=True)]
    r2_defenses = [BlueTeamDefense(finding_id="F-001", is_false_positive=True, counter_argument="Strong rebuttal")]
    payload = [{"finding_id": "F-001", "confirmed": False, "reasoning": "New defense is convincing", "patch": None}]

    result = _run_judge_r2_with_mock(confirmed, r1_verdicts, r2_defenses, "code", payload)

    assert len(result) == 1
    assert result[0].confirmed is False


def test_blue_team_r2_node_skips_when_no_confirmed():
    """blue_team_r2_node returns {} when no findings are confirmed."""
    state = PipelineState(
        code="code",
        findings=[_finding("F-001")],
        defenses=[_defense("F-001")],
        verdicts=[_verdict("F-001", confirmed=False)],
        report=DebateReport(findings=[_finding("F-001")], defenses=[_defense("F-001")], verdicts=[_verdict("F-001", confirmed=False)]),
    )
    with patch("orchestrator.graph.run_blue_team_round2") as mock_r2:
        result = blue_team_r2_node(state)
        mock_r2.assert_not_called()
    assert result == {}


def test_final_verdicts_returns_round2_when_present():
    """final_verdicts() returns round2_verdicts when they exist."""
    r1 = [_verdict("F-001", confirmed=True)]
    r2 = [_verdict("F-001", confirmed=False)]
    report = DebateReport(
        findings=[_finding()],
        defenses=[_defense()],
        verdicts=r1,
        round2_verdicts=r2,
    )
    assert final_verdicts(report) == r2


def test_final_verdicts_falls_back_to_round1():
    """final_verdicts() returns verdicts when round2_verdicts is None."""
    r1 = [_verdict("F-001", confirmed=True)]
    report = DebateReport(
        findings=[_finding()],
        defenses=[_defense()],
        verdicts=r1,
        round2_verdicts=None,
    )
    assert final_verdicts(report) == r1


def test_judge_r2_keeps_confirmed_when_defense_is_weak():
    """run_judge_round2 keeps confirmed=True when judge disagrees with new defense."""
    confirmed = [_finding("F-001")]
    r1_verdicts = [_verdict("F-001", confirmed=True)]
    r2_defenses = [BlueTeamDefense(finding_id="F-001", is_false_positive=True, counter_argument="Weak argument")]
    payload = [{"finding_id": "F-001", "confirmed": True, "reasoning": "Defense not convincing", "patch": None}]

    result = _run_judge_r2_with_mock(confirmed, r1_verdicts, r2_defenses, "code", payload)

    assert result[0].confirmed is True
