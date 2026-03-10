import json
from unittest.mock import MagicMock, patch
from agents.blue_team import run_blue_team
from utils.schemas import BlueTeamDefense, RedTeamFinding


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


def _mock_response(payload: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.content = json.dumps(payload)
    return mock


def _run_with_mock(findings, code, payload):
    """Run run_blue_team with a mocked LLM that returns the given payload."""
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)

    with patch("agents.blue_team.ChatGroq"), \
         patch("agents.blue_team.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_blue_team(findings, code)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_run_blue_team_returns_list_of_defenses():
    payload = [{"finding_id": "F-001", "is_false_positive": False, "counter_argument": "Input is not validated."}]
    result = _run_with_mock([_finding("F-001")], "def foo(): pass", payload)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], BlueTeamDefense)


def test_is_false_positive_true_parsed_correctly():
    payload = [{"finding_id": "F-001", "is_false_positive": True, "counter_argument": "Input is validated upstream."}]
    result = _run_with_mock([_finding("F-001")], "def foo(): pass", payload)

    assert result[0].is_false_positive is True


def test_is_false_positive_false_parsed_correctly():
    payload = [{"finding_id": "F-001", "is_false_positive": False, "counter_argument": "No sanitization found."}]
    result = _run_with_mock([_finding("F-001")], "def foo(): pass", payload)

    assert result[0].is_false_positive is False


def test_finding_id_preserved():
    payload = [{"finding_id": "F-042", "is_false_positive": False, "counter_argument": "Genuine risk."}]
    result = _run_with_mock([_finding("F-042")], "def foo(): pass", payload)

    assert result[0].finding_id == "F-042"


def test_multiple_findings_returns_multiple_defenses():
    payload = [
        {"finding_id": "F-001", "is_false_positive": False, "counter_argument": "Real issue."},
        {"finding_id": "F-002", "is_false_positive": True, "counter_argument": "Dead code path."},
        {"finding_id": "F-003", "is_false_positive": False, "counter_argument": "No escaping."},
    ]
    findings = [_finding("F-001"), _finding("F-002"), _finding("F-003")]
    result = _run_with_mock(findings, "def foo(): pass", payload)

    assert len(result) == 3
    assert result[1].is_false_positive is True
    assert result[2].is_false_positive is False


def test_counter_argument_is_nonempty():
    payload = [{"finding_id": "F-001", "is_false_positive": False, "counter_argument": "Detailed analysis here."}]
    result = _run_with_mock([_finding("F-001")], "def foo(): pass", payload)

    assert len(result[0].counter_argument) > 0


def test_markdown_fence_stripped():
    raw_payload = [{"finding_id": "F-001", "is_false_positive": False, "counter_argument": "Genuine."}]
    fenced = "```json\n" + json.dumps(raw_payload) + "\n```"

    mock_response = MagicMock()
    mock_response.content = fenced
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = mock_response

    with patch("agents.blue_team.ChatGroq"), \
         patch("agents.blue_team.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        result = run_blue_team([_finding("F-001")], code="def foo(): pass")

    assert len(result) == 1
    assert result[0].finding_id == "F-001"


def test_empty_findings_returns_empty_list():
    payload = []
    result = _run_with_mock([], "def foo(): pass", payload)

    assert result == []
