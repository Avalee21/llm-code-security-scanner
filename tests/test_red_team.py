import json
from unittest.mock import MagicMock, patch
from agents.red_team import run_red_team
from utils.schemas import RedTeamFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(payload: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.content = json.dumps(payload)
    return mock


def _run_with_mock(code: str, payload: list[dict]):
    """Run run_red_team with a mocked LLM that returns the given payload."""
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)

    with patch("agents.red_team.ChatGroq"), \
         patch("agents.red_team.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_red_team(code)


SAMPLE_PAYLOAD = {
    "finding_id": "F-001",
    "cwe_id": "CWE-89",
    "cwe_name": "SQL Injection",
    "severity": "high",
    "vulnerable_code": "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
    "exploit_argument": "uid is unsanitized",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_run_red_team_returns_list_of_findings():
    result = _run_with_mock("def foo(): pass", [SAMPLE_PAYLOAD])

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], RedTeamFinding)


def test_finding_fields_parsed_correctly():
    result = _run_with_mock("def foo(): pass", [SAMPLE_PAYLOAD])

    f = result[0]
    assert f.finding_id == "F-001"
    assert f.cwe_id == "CWE-89"
    assert f.cwe_name == "SQL Injection"
    assert f.severity == "high"
    assert f.exploit_argument == "uid is unsanitized"


def test_multiple_findings():
    payload = [
        {**SAMPLE_PAYLOAD, "finding_id": "F-001"},
        {**SAMPLE_PAYLOAD, "finding_id": "F-002", "cwe_id": "CWE-22", "cwe_name": "Path Traversal"},
        {**SAMPLE_PAYLOAD, "finding_id": "F-003", "severity": "critical"},
    ]
    result = _run_with_mock("def foo(): pass", payload)

    assert len(result) == 3
    assert result[1].cwe_id == "CWE-22"
    assert result[2].severity == "critical"


def test_empty_findings_returns_empty_list():
    result = _run_with_mock("def foo(): pass", [])
    assert result == []


def test_markdown_fence_stripped():
    raw_payload = [SAMPLE_PAYLOAD]
    fenced = "```json\n" + json.dumps(raw_payload) + "\n```"

    mock_response = MagicMock()
    mock_response.content = fenced
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = mock_response

    with patch("agents.red_team.ChatGroq"), \
         patch("agents.red_team.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        result = run_red_team("def foo(): pass")

    assert len(result) == 1
    assert result[0].finding_id == "F-001"


def test_finding_id_preserved():
    payload = [{**SAMPLE_PAYLOAD, "finding_id": "F-042"}]
    result = _run_with_mock("def foo(): pass", payload)

    assert result[0].finding_id == "F-042"


def test_exploit_argument_is_nonempty():
    result = _run_with_mock("def foo(): pass", [SAMPLE_PAYLOAD])
    assert len(result[0].exploit_argument) > 0
