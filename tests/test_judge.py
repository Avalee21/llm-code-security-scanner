import json
from unittest.mock import MagicMock, patch

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


def _mock_response(payload: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.content = json.dumps(payload)
    return mock


def _verdict_payload(finding_id: str, confirmed: bool) -> dict:
    return {
        "finding_id": finding_id,
        "confirmed": confirmed,
        "reasoning": f"Analysis for {finding_id}",
        "patch": None,
    }


def _run_with_mock(findings, defenses, code, payload):
    """Run run_judge with a mocked LLM that returns the given payload."""
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)

    with patch("agents.judge_patcher.get_llm"), \
         patch("agents.judge_patcher.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_judge(findings, defenses, code)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_judge_returns_list_of_verdicts():
    payload = [_verdict_payload("F-001", True)]
    result = _run_with_mock(
        [_finding("F-001")],
        [_defense("F-001", is_false_positive=False)],
        "def foo(): pass",
        payload,
    )

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], JudgeVerdict)


def test_judge_all_confirmed():
    payload = [_verdict_payload("F-001", True), _verdict_payload("F-002", True)]
    result = _run_with_mock(
        [_finding("F-001"), _finding("F-002")],
        [_defense("F-001", is_false_positive=False), _defense("F-002", is_false_positive=False)],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 2
    assert all(v.confirmed is True for v in result)
    assert all(v.patch is None for v in result)


def test_judge_all_false_positive():
    payload = [_verdict_payload("F-001", False), _verdict_payload("F-002", False)]
    result = _run_with_mock(
        [_finding("F-001"), _finding("F-002")],
        [_defense("F-001", is_false_positive=True), _defense("F-002", is_false_positive=True)],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 2
    assert all(v.confirmed is False for v in result)


def test_judge_mixed():
    payload = [_verdict_payload("F-001", True), _verdict_payload("F-002", False)]
    result = _run_with_mock(
        [_finding("F-001"), _finding("F-002")],
        [_defense("F-001", is_false_positive=False), _defense("F-002", is_false_positive=True)],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 2
    verdict_map = {v.finding_id: v for v in result}
    assert verdict_map["F-001"].confirmed is True
    assert verdict_map["F-002"].confirmed is False


def test_judge_no_defenses():
    payload = [
        _verdict_payload("F-001", True),
        _verdict_payload("F-002", True),
        _verdict_payload("F-003", True),
    ]
    result = _run_with_mock(
        [_finding("F-001"), _finding("F-002"), _finding("F-003")],
        [],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 3
    assert all(v.confirmed is True for v in result)


def test_judge_empty_inputs():
    verdicts = run_judge(findings=[], defenses=[], code="def foo(): pass")
    assert verdicts == []


def test_judge_finding_id_preserved():
    payload = [_verdict_payload("F-042", True)]
    result = _run_with_mock(
        [_finding("F-042")],
        [],
        "def foo(): pass",
        payload,
    )

    assert result[0].finding_id == "F-042"


def test_judge_reasoning_is_nonempty():
    payload = [_verdict_payload("F-001", True), _verdict_payload("F-002", False)]
    result = _run_with_mock(
        [_finding("F-001"), _finding("F-002")],
        [_defense("F-001", is_false_positive=False)],
        "def foo(): pass",
        payload,
    )

    assert all(len(v.reasoning) > 0 for v in result)


def test_judge_markdown_fence_stripped():
    raw_payload = [_verdict_payload("F-001", True)]
    fenced = "```json\n" + json.dumps(raw_payload) + "\n```"

    mock_response = MagicMock()
    mock_response.content = fenced
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = mock_response

    with patch("agents.judge_patcher.get_llm"), \
         patch("agents.judge_patcher.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        result = run_judge(
            [_finding("F-001")],
            [_defense("F-001", is_false_positive=False)],
            "def foo(): pass",
        )

    assert len(result) == 1
    assert result[0].finding_id == "F-001"
    assert result[0].confirmed is True


def test_judge_missing_verdict_gets_default():
    # LLM only returns verdict for F-001, not F-002
    payload = [_verdict_payload("F-001", False)]
    result = _run_with_mock(
        [_finding("F-001"), _finding("F-002")],
        [_defense("F-001", is_false_positive=True), _defense("F-002", is_false_positive=False)],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 2
    verdict_map = {v.finding_id: v for v in result}
    assert verdict_map["F-001"].confirmed is False
    # F-002 should get default confirmed=True since LLM didn't return it
    assert verdict_map["F-002"].confirmed is True
    assert "default" in verdict_map["F-002"].reasoning.lower()


def test_judge_confirmed_with_patch():
    """Confirmed verdicts can carry a non-null patch."""
    payload = [{
        "finding_id": "F-001",
        "confirmed": True,
        "reasoning": "Genuine SQL injection",
        "patch": "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
    }]
    result = _run_with_mock(
        [_finding("F-001")],
        [_defense("F-001", is_false_positive=False)],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 1
    assert result[0].confirmed is True
    assert result[0].patch == "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))"


def test_judge_dismissed_has_null_patch():
    """Dismissed verdicts should have patch=None."""
    payload = [{
        "finding_id": "F-001",
        "confirmed": False,
        "reasoning": "Not exploitable",
        "patch": None,
    }]
    result = _run_with_mock(
        [_finding("F-001")],
        [_defense("F-001", is_false_positive=True)],
        "def foo(): pass",
        payload,
    )

    assert len(result) == 1
    assert result[0].confirmed is False
    assert result[0].patch is None
